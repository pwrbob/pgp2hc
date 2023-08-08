target=x86_64-pc-windows-gnu

## 1. install cross:
if ! command -v cross &> /dev/null
then
    echo "the command 'cross' could not be found, install with 'cargo install cross'"
    exit
fi

## 2. run cross

cross build --target ${target} --release
