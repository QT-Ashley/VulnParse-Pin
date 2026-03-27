# Installation

VulnParse-Pin is a Python-based tool that can be installed using pip. Follow the instructions below to set up VulnParse-Pin on your system. It has been designed to work on Linux, macOS, and Windows platforms. Standalone executables are also available for users who prefer not to manage Python dependencies.

See the [Usage Guide](Usage.md) for instructions on how to run VulnParse-Pin after installation. For any issues during installation, please refer to the [Known Limitations](Known%20Limitations.md) document or contact support.

> Standalone executables are available for users who prefer not to manage Python dependencies. Please download here at [VulnParse-Pin Releases](https://www.github.com/QT-Ashley/vulnparse-pin/releases) and follow the repo README instructions for usage. Note that standalone executables may have limitations compared to the full Python package, such as reduced enrichment capabilities or limited parser support. For full functionality, we recommend installing via pip.

## Python Package Installation

1. Ensure you have Python 3.12 or later installed on your system. You can check your Python version by running:

   ```bash
   python --version
   ```

2. Install VulnParse-Pin using pip:

   ```bash
   pip install vulnparse-pin
   ```

3. After installation, you can verify that VulnParse-Pin is installed correctly by running:

   ```bash
    vpp --help
    or
    vpp -h
    ```

    This should display the help message for VulnParse-Pin, confirming that it is ready to use.
4. Check current version by running:

    ```bash
    vpp --version
    or
    vpp -v
    ```

    This should display the installed version of VulnParse-Pin.

## Standalone Executable Installation

1. Download the latest standalone executable for your platform from the [VulnParse-Pin Releases](https://www.github.com/QT-Ashley/vulnparse-pin/releases) page.

2. Follow the included README instructions for usage. Note that standalone executables may have limitations compared to the full Python package, such as reduced enrichment capabilities or limited parser support. For full functionality, we recommend installing via pip.

3. After downloading, you can run the executable from your command line or terminal. For example:

   ```bash
   ./vulnparse-pin --help
   ```

    or on Windows:

   ```bash
   vulnparse-pin.exe --help
   ```

   This should display the help message for VulnParse-Pin, confirming that it is ready to use.

4. Check current version by running:

   ```bash
   ./vulnparse-pin --version
   ```

    or on Windows:

   ```bash
   vulnparse-pin.exe --version
   ```

   This should display the installed version of VulnParse-Pin.

## Additional Notes

- For users who encounter issues during installation, please refer to the [Known Limitations](Known%20Limitations.md) document for potential workarounds and troubleshooting tips.

- If you have any questions or need further assistance, please contact our support team at [support@vulnparse-pin.com](mailto:support@vulnparse-pin.com).

- For detailed usage instructions, please refer to the [Usage Guide](Usage.md).

- Always ensure you are using the latest version of VulnParse-Pin to benefit from new features, improvements, and security patches. You can check for updates on the [VulnParse-Pin Releases](https://www.github.com/QT-Ashley/vulnparse-pin/releases) page.

- For users interested in contributing to the project or reporting issues, please visit our [GitHub repository](https://www.github.com/QT-Ashley/vulnparse-pin) and follow the contribution guidelines.

### Standalone Executables

- Standalone executables are provided for convenience but may not receive updates as frequently as the Python package. For the best experience and access to the latest features, we recommend using the Python package installation method.

- Standalone executables are available as contained versions of VulnParse-Pin that do not require Python or pip. They are ideal for users who want a quick setup without managing dependencies. However, they may have limitations in terms of functionality and enrichment capabilities compared to the full Python package. For users who require the full feature set, we recommend installing VulnParse-Pin via pip as described in the Python Package Installation section above.

- To use the standalone execututables from the command line, navigate to the directory where the executable is located and run it with the desired options. You can also add the directory containing the executable to your system's PATH environment variable for easier access from any location in the terminal. 