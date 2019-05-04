# socks-proky-tunnel

## Descripition
Create a base server to allow users a UI for creating a proxy tunnel.

### Features:
1. Can be used localy for your own use, or deployed and be used by multiple users to create multiple tunnels at the same time
2. The connection to the server itself is over the secured SSH protocol
3. Uses the SOCKS5 proxy protocol
4. Can chain up inifinite amount of proxy servers
5. Supports Chaining through TOR as well
6. Easy browser integration for Firefox users

## Examples

<p align="center">
  <img src="/Examples/1.png" width="600">
  <img src="/Examples/2.png" width="600">
</p>

## Dependencies

1. Python 3
2. Twisted 
```
pip3 install Twisted
```
3. Has been tested only on linux enviroment (please don't do proxy stuff on Windows, ever).

## How to use locally

1. Open a terminal window and run the server.py file
2. Open a second terminal window:
```
ssh -p 22222 admin@localhost
```
3. Type help to learn the commands
4. after creating your tunnel, the easiest way to route your internet usage through it is via the Firefox browser settings.

## How to use on a server

1. Deploy this to your server and use just like you would've locally.
