1. Install Docker
2. Install Nodejs 22.11.0+
3. Clone the repository:

```sh
git clone https://github.com/sola-st/PoCGen
cd PoCGen
```
4. Install dependencies:

```sh
npm install
```
5. Build the docker image:

```sh
docker build -t patched_node -f patched_node.Dockerfile .
docker build -t gen-poc_mnt .
```

