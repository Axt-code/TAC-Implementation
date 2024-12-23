# TAC-Implementation

## RP Coconut

### Setting Up the Project

Remove the previous build files:

```
rm -rf build
```

### Compile and deploy the smart contracts:

```
truffle migrate --reset --compile-all 
```

### Update the 2_deploy_contract.js file in the /migrations/ directory:

  Set Issuer0Address to the first address from Ganache.

  Set ServiceProviderAddress to the second-to-last address from Ganache.
  
### Update the constants.py file:

  change TOTAL_ISSUERS and THRESHOLD_ISSUERS to required value.

### Running the Trusted Third Party (TTP)

Run the TTP script with the following command:

```
python3 trustedTTP.py --req-ip 127.0.0.1 --req-port 3001 --total-issuers 4 --threshold-issuers 3
```

### Running Issuer Nodes

Run the following commands for each issuer node, substituting the --address with the respective issuer address:

Issuer 0

```
python3 issuer.py --req-ip 127.0.0.1 --req-port 3001 --address <first-address-of-ganache> --rpc-endpoint "http://<ganache-ip>:<ganache-port>" --Issuer I0 -I0
```

Issuer 1

```
python3 issuer.py --req-ip 127.0.0.1 --req-port 3002 --address <first-address-of-ganache> --rpc-endpoint "http://<ganache-ip>:<ganache-port>"  --Issuer I1
```

Issuer 2
```
python3 issuer.py --req-ip 127.0.0.1 --req-port 3003 --address <first-address-of-ganache> --rpc-endpoint "http://<ganache-ip>:<ganache-port>" --Issuer I2
```

### Running the User Node

Run the following command for the user node:

```
python3 user.py --address 0x65c84f201deF0531b99FfA24c72DaEbBD261218A --rpc-endpoint "http://127.0.0.1:7545"
```

### Running the Service Provider

Run the service provider script:
```
python3 service_provider.py
```


## Threshold BBS

### Setting Up the Project

Remove the previous build files:

```
rm -rf build
```

### Compile and deploy the smart contracts:

```
truffle migrate --reset --compile-all > SC_output.txt
```

### Update the 2_deploy_contract.js file in the /migrations/ directory:

  Set Issuer0Address to the first address from Ganache.
  
  Set ServiceProviderAddress to the second-to-last address from Ganache.

### Running the Trusted Third Party (TTP)

Run the TTP script with the following command:

```
python3 ttp.py --req-ip 127.0.0.1 --req-port 3000 --total-issuers 4 --threshold-issuers 3
```

### Running Issuer Nodes

Run the following commands for each issuer node, substituting the --address with the respective issuer address:

Issuer 0

```
python3 issuer.py -M4 --req-ip 127.0.0.1 --req-port 3001 --address <first-address-of-ganache> --rpc-endpoint "http://<ganache-ip>:<ganache-port>" --Issuer I0 -I0
```

Issuer 1

```
python3 issuer.py -M4 --req-ip 127.0.0.1 --req-port 3002 --address <second-address-of-ganache> --rpc-endpoint "http://<ganache-ip>:<ganache-port>" --Issuer I1 -I1
```

Issuer 2

```
python3 issuer.py -M4 --req-ip 127.0.0.1 --req-port 3003 --address <third-address-of-ganache> --rpc-endpoint "http://<ganache-ip>:<ganache-port>" --Issuer I2 -I2
```

Issuer 3

```
python3 issuer.py -M4 --req-ip 127.0.0.1 --req-port 3004 --address <forth-address-of-ganache> --rpc-endpoint "http://<ganache-ip>:<ganache-port>" --Issuer I3 -I3
```

### Running the User Node

Run the following command for the user node:

```
python3 user.py --address <last-address-of-ganache> --total-issuers 4 --threshold-issuers 3
```

### Running the Service Provider

Run the service provider script:

```
python3 service_provider.py
```

## Threshold BBS+

### Setting Up the Project

Remove the previous build files:

```
rm -rf build
```

### Compile and deploy the smart contracts:

```
truffle migrate --reset --compile-all > SC_output.txt
```

### Update the 2_deploy_contract.js file in the /migrations/ directory:

  Set Issuer0Address to the first address from Ganache.
  
  Set ServiceProviderAddress to the second-to-last address from Ganache.

### Running the Trusted Third Party (TTP)

Run the TTP script with the following command:

```
python3 ttp.py --req-ip 127.0.0.1 --req-port 3000 --total-issuers 4 --threshold-issuers 3
```

### Running Issuer Nodes

Run the following commands for each issuer node, substituting the --address with the respective issuer address:

Issuer 0

```
python3 issuer.py -M4 --req-ip 127.0.0.1 --req-port 3001 --address <first-address-of-ganache> --rpc-endpoint "http://<ganache-ip>:<ganache-port>" --Issuer I0 -I0
```

Issuer 1

```
python3 issuer.py -M4 --req-ip 127.0.0.1 --req-port 3002 --address <second-address-of-ganache> --rpc-endpoint "http://<ganache-ip>:<ganache-port>" --Issuer I1 -I1
```

Issuer 2

```
python3 issuer.py -M4 --req-ip 127.0.0.1 --req-port 3003 --address <third-address-of-ganache> --rpc-endpoint "http://<ganache-ip>:<ganache-port>" --Issuer I2 -I2
```

Issuer 3

```
python3 issuer.py -M4 --req-ip 127.0.0.1 --req-port 3004 --address <forth-address-of-ganache> --rpc-endpoint "http://<ganache-ip>:<ganache-port>" --Issuer I3 -I3
```

### Running the User Node

Run the following command for the user node:

```
python3 user.py --address <last-address-of-ganache> --total-issuers 4 --threshold-issuers 3
```

### Running the Service Provider

Run the service provider script:

```
python3 service_provider.py
```
