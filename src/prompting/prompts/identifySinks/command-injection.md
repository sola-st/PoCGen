## Example input:

```
0. exec(args.join(' '))
1. system(`echo ${var}`)
2. fs.readFileSync(file)
```

## Example output:

[0,1]

`0` because the function name `exec` indicates a call to an external program.
`1` because the argument looks like a shell command.
