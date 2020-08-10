# scanNport

[![Language](https://img.shields.io/badge/Bash-4.2%2B-brightgreen.svg?style=for-the-badge)]()
[![Build](https://img.shields.io/badge/Supported_OS-Linux-orange.svg?style=for-the-badge)]()
[![Download](https://img.shields.io/badge/Size-12.3KB-brightgreen.svg?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-GPL%20v3%2B-red.svg?style=for-the-badge)](https://github.com/hacknonym/scanNport/blob/master/LICENSE)

### Author: github.com/hacknonym

##  A Network Mapper for Post Exploitation

![Banner](https://user-images.githubusercontent.com/55319869/89815732-8f340980-db45-11ea-81d8-ef30f3f2e933.png)

**scanNport** scan hosts and TCP ports. #scanner #network #mapper #scan #scanNport

## Features !
- Not necessary to have root rights
- Only essential dependances (ping)

### Usage without Download
```bash
wget -q -O - https://raw.githubusercontent.com/hacknonym/scanNport/master/scanNport.sh | bash /dev/stdin <arg1> <arg2> <arg3>
curl -s https://raw.githubusercontent.com/hacknonym/scanNport/master/scanNport.sh | bash /dev/stdin <arg1> <arg2> <arg3>

e.g. 
curl -s https://raw.githubusercontent.com/hacknonym/scanNport/master/scanNport.sh | bash /dev/stdin 10.0.0.0/16 -s
curl -s https://raw.githubusercontent.com/hacknonym/scanNport/master/scanNport.sh | bash /dev/stdin 10.0.0.0/16 -p 20,21,22,23,25,80
```

### Usage 
```bash
git clone https://github.com/hacknonym/scanNport.git
cd scanNport
chmod +x scanNport.sh
./scanNport.sh --help
```

## Detect TCP ports
Just send a TCP packet using '/dev/tcp'
```bash
if echo "test" 2> /dev/null > /dev/tcp/<IP_ADDRESS>/<PORT> ; then
  echo -e "TCP <PORT> is Open on <IP_ADDRESS>"
fi
```

## Tools Overview
![Help](https://user-images.githubusercontent.com/55319869/89815932-e639de80-db45-11ea-974a-cc435c06a50e.png)
![All ports](https://user-images.githubusercontent.com/55319869/89815920-e33eee00-db45-11ea-8147-9214dee234b4.png)
![Common ports](https://user-images.githubusercontent.com/55319869/89815925-e4701b00-db45-11ea-83a5-df0faf6c3e75.png)
![Specific ports](https://user-images.githubusercontent.com/55319869/89815937-e89c3880-db45-11ea-94bd-d101eb3318a9.png)
![Ping scan](https://user-images.githubusercontent.com/55319869/89815934-e76b0b80-db45-11ea-8c80-d97e5550ffc8.png)

## License
GNU General Public License v3.0 for scanNport
AUTHOR: @hacknonym
