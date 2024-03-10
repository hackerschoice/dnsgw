# DNSGW

## Using `tunnelcli`

The `tunnelcli` tool is designed to interact with the backend API, allowing you to manage tunnels from the command line.

To configure the `tunnelcli` tool to interact with a custom backend API, you can set the `TUNNELCLI_API_BASE_URL` environment variable. This allows you to specify the base URL of the API that `tunnelcli` will communicate with. If this environment variable is not set, `tunnelcli` defaults to using `http://localhost:8080` as the base URL.

For example, to set the API base URL to `https://api.example.com`, you can use the following command in your terminal:

```shell
TUNNELCLI_API_BASE_URL=https://api.example.com ./tunnelcli ...
```

### Commands

- **Create a Tunnel**: Creates a new tunnel with the specified IP and port.
    ```shell
    ./tunnelcli dns2tcpd create [ip] [port]
    ```


- **Update a Tunnel**: Updates an existing tunnel with new resources.
    ```shell
    ./tunnelcli dns2tcpd update [updateKey] [resourceName,ip,port] [resourceName2,ip2,port2]
    ```


- **Get Configuration**: Retrieves the configuration for a specific resource.
  ```shell
  ./tunnelcli dns2tcpd get-config [updateKey] [resource] [local port]
  ```


### API Endpoints

#### Create Tunnel
- **Method**: POST
- **URL**: `/v1/dns2tcpd/create/:ip/:port`
- **Description**: Creates a new tunnel with the specified IP and port.
- **Body**: No request body is required for this endpoint. The IP and port are specified in the URL.
- **Success Response**:
  - **Code**: 200 OK
  - **Content**:
  ```
    {
      "target": "generated_domain_name",
      "key": "unique_key_for_tunnel",
      "updateKey": "unique_update_key"
    }
  ```
- **Error Response**:
  - **Code**: 400 Bad Request / 500 Internal Server Error
  - **Content**:
  ```
    {
      "error": "Error message"
    }
  ```

#### Update Tunnel
- **Method**: PUT
- **URL**: `/v1/dns2tcpd/update`
- **Description**: Updates an existing tunnel with new resources.
- **Body**:
```
  {
    "update_key": "unique_update_key",
    "resources": [
      {
        "name": "resource1",
        "ip": "192.168.1.100",
        "port": 8080
      },
      {
        "name": "resource2",
        "ip": "192.168.1.101",
        "port": 8081
      }
    ]
  }
  ```
  - `update_key`: The unique key provided when the tunnel was created or last updated.
  - `resources`: An array of resources to be updated. Each resource includes a `name`, `ip`, and `port`.
- **Success Response**:
  - **Code**: 200 OK
  - **Content**:
  ```
    {
      "message": "Tunnel updated successfully",
      "status": "waiting",
    }
  ```
- **Error Response**:
  - **Code**: 400 Bad Request / 404 Not Found / 500 Internal Server Error
  - **Content**:
  ```
    {
      "error": "Error message"
    }
  ```
#### Get DNS2TCPD Configuration
- **Method**: POST
- **URL**: `/v1/dns2tcpd/config`
- **Description**: Retrieves the configuration for a specific resource.
- **Body**:
```
  {
    "update_key": "unique_update_key",
    "resource": "resource_name",
    "local_port": 8080
  }
```
  - `update_key`: The unique key associated with the tunnel.
  - `resource`: The name of the resource for which the configuration is requested.
  - `local_port`: The local port number associated with the resource.
- **Success Response**:
  - **Code**: 200 OK
  - **Content**:
  ```
    {
      "config": "Configuration details"
    }
  ```
- **Error Response**:
  - **Code**: 400 Bad Request / 404 Not Found / 500 Internal Server Error
  - **Content**:
  ```
    {
      "error": "Error message"
    }
    ```


## AppConfig Options

The `AppConfig` struct in `config.go` defines several configuration options for the tunnel management system. Below is a detailed explanation of each option:

- `Dns2tcpdConfigPath`: Specifies the directory path where DNS2TCPD configuration files are stored. Default is `/tmp/dns-configs/`.

- `DomainName`: The domain name used for the DNS tunnels. Currently, the system is designed to support a single domain, e.g., `abc.io`, although we'll probably adapt it to support multiple domains.. at some point...

- `WatchDogTimeout`: Defines the duration after which the watchdog process will check for inactive or stale tunnels. The default timeout is set to 15 minutes (`15 * time.Minute`).

- `AccessMode`: Determines the access control mode for creating and managing tunnels. It can be one of the following:
  - `PublicMode`: No authentication is required to create or manage tunnels.
  - `TokenRequiredMode`: A valid token must be provided for tunnel operations.
  - `PreSharedKeyMode`: Operations require a pre-shared key, specified in the `Key` field of the `PreSharedKeyMode` struct.

- `LogLevel`: Sets the logging level for the application. Uses levels defined by the `logrus` package, e.g., `logrus.DebugLevel`.

- `BlacklistedCIDRs`: A list of CIDR ranges that are not allowed to be used for tunnel IP addresses. This is useful for preventing the use of private, reserved, or otherwise restricted IP ranges. Example: `[]string{"192.168.1.0/24"}`.