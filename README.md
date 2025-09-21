# KubeCAP

## Build

### MacOS

```shell
brew install libpcap
```

```shell
export CGO_ENABLED=1
export CGO_LDFLAGS="-L/opt/homebrew/opt/libpcap/lib"
make build
```

## Usage

```shell
sudo ./bin/kubecap en0
```