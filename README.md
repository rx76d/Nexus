<h1>
  Nexus
  <img src="icon.ico" align="right" width="80"/>
</h1>

![Version](https://img.shields.io/badge/version-1.0.2-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

Nexus helps you manage your emails keep track of which email you’re using for which services and securely store your passwords locally.

## Features

*   **Identity Zones:** You can organise your emails into different zones (Professional, Private, Social, Ghost). You never have to guess which email to use.

*   **Anti-Brute Force:** Fails the password 3 times? The system locks down for an hour. Fails security questions? It locks for two.

*   **Email Inventory:** Keeps track of every email address you own, its status (Active/Dormant), and what you use it for.

*   **Custom Themes:** Toggle between Light, Dark, or System themes to match your setup.


## How to Run (Windows Only)

1. **Go to the **[Releases](../../releases)** section on the right.**

2. **Download `NexusManager.exe`.**

3. **Double-click to run.**

> It will create a folder named My_Digital_Nexus containing two files nexus_data.db and security.key .


## How to Run (Mac / Linux / Developer Mode)

*Since `.exe` files are for Windows, Mac and Linux users should run the app directly from the source code.*

1. **Clone the Repository:**
    ```bash
    git clone https://github.com/rx76d/Nexus.git
    cd Nexus
    ```

2.  **Install Required Libraries:**
    ```bash
    pip install -r requirements.txt
    ```
    >*(Linux users might get a Tkinter error, to fix it run **`sudo apt-get install python3-tk`**).*

3.  **Run the app:**
    ```bash
    python nexus_manager.py
    ```
    >*(Note: On Mac/Linux, you might need to use `python3` instead of `python`).*

4.  (Optional) **To Build a standalone app for your OS, run this in your terminal:**
    ```bash
    pyinstaller --noconsole --onefile --name "NexusManager" --icon="icon.ico" nexus_manager.py
    ```

## License

This project is open source and available under the MIT License.

<br>

<div align="center">
<sub>Developed by rx76d</sub>
</div>