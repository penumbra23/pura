# Notes

## Description

If you encounter some error to run the pura runtime from build try these steps

## Usage

Make this to clean the way:
```sh
set ID=example
[sudo] unlink /tmp/pura/${ID}/init.sock
[sudo] unlink /tmp/pura/${ID}/container.sock
```

On another terminal:
```sh
[sudo] nc -vklU /tmp/${ID}.sock # on another terminal
```

On the config.json
```sh
...
"root": {
  "path": "/absolute/path/to/rootfs"
}
...
```

Now on pura context
```sh
cd target/release
./pura create ${ID} --bundle /path/to/bundle --console-sock /tmp/${ID}.sock
./pura start ${ID}
./pura state ${ID}
./pura delete ${ID}
```
