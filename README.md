# VaccineX

VaccineX is a distributed marketplace for genome data used in vaccine development. Most viruses mutates over time and in order to be up to date in a vaccine development proccess research teams must have access to recent genome mutations. 

## Requirements
1. Require python version >=3.6.8 , so make sure your python version is okay.
2. Make sure you have installed docker

## Getting started

1. Clone this repository
2. Create .env file in a repository root directory and provide rinkeby rpc endpoint, 3 ursula providers and ipfs api endpoint
3. Build docker container by typing `docker build --tag vaccinex-nucypher:1.0 .`
4. Run docker container by `docker run --publish 5000:5000 --detach --name nucypher-service vaccinex-nucypher:1.0`
4. Check port :5000