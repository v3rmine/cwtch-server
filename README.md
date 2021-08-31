# Cwtch Server

## Running

- cd app
- go build
- ./app

The app takes the following arguments
- -debug: enabled debug logging
- -exportTofuBundle: Export the tofubundle to a file called tofubundle


The app takes the following environment variables
- CWTCH_HOME: sets the config dir for the app

## Using the Server

When run the app will output standard log lines, one of which will contain the `tofubundle` in purple. This is the part you need to capture and import into a Cwtch client app so you can use the server for hosting groups

## Docker

Build by executing `docker build -f docker/Dockerfile .`

or run our prebuild ones with 

`pull openpriv:cwtch-server`

and run it. It stores all Cwtch data in a Volume at `/var/lib/cwtch`

