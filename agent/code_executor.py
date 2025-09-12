import logging
import os
import random
import shlex
import string
import subprocess
from pathlib import Path
from typing import Iterator, Literal, Optional

import docker
from forge.agent.components import ConfigurableComponent
from forge.agent.protocols import CommandProvider
from forge.command import Command, command
from forge.file_storage import FileStorage
from forge.models.json_schema import JSONSchema
from forge.utils.exceptions import (
    CommandExecutionError,
    InvalidArgumentError,
    OperationNotAllowedError,
)
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


def we_are_running_in_a_docker_container() -> bool:
    """Check if we are running in a Docker container

    Returns:
        bool: True if we are running in a Docker container, False otherwise
    """
    return os.path.exists("/.dockerenv")


def is_docker_available() -> bool:
    """Check if Docker is available and supports Linux containers

    Returns:
        bool: True if Docker is available and supports Linux containers, False otherwise
    """
    try:
        client = docker.from_env()
        docker_info = client.info()
        return docker_info["OSType"] == "linux"
    except Exception:
        return False


class CodeExecutionError(CommandExecutionError):
    """The operation (an attempt to run arbitrary code) returned an error"""


class CodeExecutorConfiguration(BaseModel):
    execute_local_commands: bool = True
    """Enable shell command execution"""
    shell_command_control: Literal["allowlist", "denylist"] = "allowlist"
    """Controls which list is used"""
    shell_allowlist: list[str] = Field(default_factory=list)
    """List of allowed shell commands"""
    shell_denylist: list[str] = Field(default_factory=list)
    """List of prohibited shell commands"""
    docker_container_name: str = "agent_sandbox"
    """Name of the Docker container used for code execution"""


class CodeExecutorComponent(
    CommandProvider, ConfigurableComponent[CodeExecutorConfiguration]
):
    """Provides commands to execute Python code and shell commands."""

    config_class = CodeExecutorConfiguration

    def __init__(
            self,
            workspace: FileStorage,
            config: Optional[CodeExecutorConfiguration] = None,
    ):
        ConfigurableComponent.__init__(self, config)
        self.workspace = workspace

        # Change container name if it's empty or default to prevent different agents
        # from using the same container
        default_container_name = self.config.model_fields[
            "docker_container_name"
        ].default
        if (
                not self.config.docker_container_name
                or self.config.docker_container_name == default_container_name
        ):
            random_suffix = "".join(random.choices(string.ascii_lowercase, k=8))
            self.config.docker_container_name = (
                f"{default_container_name}_{random_suffix}"
            )

        if not we_are_running_in_a_docker_container() and not is_docker_available():
            logger.info(
                "Docker is not available or does not support Linux containers. "
                "The code execution commands will not be available."
            )

        if not self.config.execute_local_commands:
            logger.info(
                "Local shell commands are disabled. To enable them,"
                " set EXECUTE_LOCAL_COMMANDS to 'True' in your config file."
            )

    def get_commands(self) -> Iterator[Command]:
        if we_are_running_in_a_docker_container() or is_docker_available():
            yield self.execute_javascript_code
            yield self.execute_javascript_file

        if self.config.execute_local_commands:
            yield self.execute_shell
            yield self.execute_shell_popen

    @command(
        ["execute_javascript_code"],
        "Executes the given JavaScript code inside a single-use Docker container"
        " with access to your workspace folder",
        {
            "code": JSONSchema(
                type=JSONSchema.Type.STRING,
                description="The JavaScript code to run",
                required=True,
            ),
        },
    )
    async def execute_javascript_code(self, code: str) -> str:
        temp_path = ""
        while True:
            temp_path = f"temp{self._generate_random_string()}.js"
            if not self.workspace.exists(temp_path):
                break
        await self.workspace.write_file(temp_path, code)

        try:
            return self.execute_javascript_file(temp_path)
        except Exception as e:
            raise CommandExecutionError(*e.args)
        finally:
            self.workspace.delete_file(temp_path)

    @command(
        ["execute_javascript_file"],
        "Execute an existing JavaScript file inside a single-use Docker container"
        " with access to your workspace folder",
        {
            "filename": JSONSchema(
                type=JSONSchema.Type.STRING,
                description="The name of the file to execute",
                required=True,
            ),
            "args": JSONSchema(
                type=JSONSchema.Type.ARRAY,
                description="The (command line) arguments to pass to the script",
                required=False,
                items=JSONSchema(type=JSONSchema.Type.STRING),
            ),
        },
    )
    def execute_javascript_file(self, filename: str | Path, args: list[str] = []) -> str:
        """
        Execute a JavaScript file in a Docker container and return the output.

        Args:
            filename (Path): The name of the file to execute.
            args (list, optional): The arguments with which to run the JavaScript script.

        Returns:
            str: The output of the file.
        """
        logger.info(f"Executing JavaScript file '{filename}'")

        if not str(filename).endswith(".js"):
            raise InvalidArgumentError("Invalid file type. Only .js files are allowed.")

        file_path = self.workspace.get_path(filename)
        if not self.workspace.exists(file_path):
            raise FileNotFoundError(
                f"node: can't open file '{filename}': "
                f"[Errno 2] No such file or directory"
            )

        if we_are_running_in_a_docker_container():
            logger.debug(
                "App is running in a Docker container; "
                f"executing {file_path} directly..."
            )
            with self.workspace.mount() as local_path:
                result = subprocess.run(
                    ["node", str(file_path.relative_to(self.workspace.root))] + args,
                    capture_output=True,
                    encoding="utf8",
                    cwd=str(local_path),
                )
                if result.returncode == 0:
                    return result.stdout
                else:
                    raise CodeExecutionError(result.stderr)

        logger.debug("App is not running in a Docker container")
        return self._run_javascript_code_in_docker(file_path, args)

    def validate_command(self, command_line: str) -> tuple[bool, bool]:
        return True, True

    @command(
        ["execute_shell"],
        "Execute a Shell Command, non-interactive commands only",
        {
            "command_line": JSONSchema(
                type=JSONSchema.Type.STRING,
                description="The command line to execute",
                required=True,
            )
        },
    )
    def execute_shell(self, command_line: str) -> str:
        """Execute a shell command and return the output

        Args:
            command_line (str): The command line to execute

        Returns:
            str: The output of the command
        """
        allow_execute, allow_shell = self.validate_command(command_line)
        if not allow_execute:
            logger.info(f"Command '{command_line}' not allowed")
            raise OperationNotAllowedError("This shell command is not allowed.")

        current_dir = Path.cwd()
        # Change dir into workspace if necessary
        if not current_dir.is_relative_to(self.workspace.root):
            os.chdir(self.workspace.root)

        logger.info(
            f"Executing command '{command_line}' in working directory '{os.getcwd()}'"
        )

        result = subprocess.run(
            command_line if allow_shell else shlex.split(command_line),
            capture_output=True,
            shell=allow_shell,
        )
        output = f"STDOUT:\n{result.stdout.decode()}\nSTDERR:\n{result.stderr.decode()}"

        # Change back to whatever the prior working dir was
        os.chdir(current_dir)

        return output

    @command(
        ["execute_shell_popen"],
        "Execute a Shell Command, non-interactive commands only",
        {
            "command_line": JSONSchema(
                type=JSONSchema.Type.STRING,
                description="The command line to execute",
                required=True,
            )
        },
    )
    def execute_shell_popen(self, command_line: str) -> str:
        """Execute a shell command with Popen and returns an english description
        of the event and the process id

        Args:
            command_line (str): The command line to execute

        Returns:
            str: Description of the fact that the process started and its id
        """
        allow_execute, allow_shell = self.validate_command(command_line)
        if not allow_execute:
            logger.info(f"Command '{command_line}' not allowed")
            raise OperationNotAllowedError("This shell command is not allowed.")

        current_dir = Path.cwd()
        # Change dir into workspace if necessary
        if not current_dir.is_relative_to(self.workspace.root):
            os.chdir(self.workspace.root)

        logger.info(
            f"Executing command '{command_line}' in working directory '{os.getcwd()}'"
        )

        do_not_show_output = subprocess.DEVNULL
        process = subprocess.Popen(
            command_line if allow_shell else shlex.split(command_line),
            shell=allow_shell,
            stdout=do_not_show_output,
            stderr=do_not_show_output,
        )

        # Change back to whatever the prior working dir was
        os.chdir(current_dir)

        return f"Subprocess started with PID:'{str(process.pid)}'"

    def _generate_random_string(self, length: int = 8):
        # Create a string of all letters and digits
        characters = string.ascii_letters + string.digits
        # Use random.choices to generate a random string
        random_string = "".join(random.choices(characters, k=length))
        return random_string
