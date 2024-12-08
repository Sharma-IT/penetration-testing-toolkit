#!/bin/bash

# Ensure script is run with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run with sudo"
    exit 1
fi

# Get the absolute path of the project directory
PROJECT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Define installation paths
INSTALL_DIR="/usr/local/share/penetration-testing-toolkit"
EXECUTABLE="/usr/local/bin/pentest"
ARTIFACTS_DIR="$INSTALL_DIR/artifacts"

# Get the current user (the one who ran sudo)
REAL_USER="${SUDO_USER:-$USER}"

# Remove existing installation if present
if [ -d "$INSTALL_DIR" ] || [ -f "$EXECUTABLE" ]; then
    echo "Removing existing installation..."
    rm -rf "$INSTALL_DIR" "$EXECUTABLE"
fi

# Create the installation directory
echo "Creating installation directory..."
mkdir -p "$INSTALL_DIR"

# Copy the entire project to the installation directory
echo "Copying project files to $INSTALL_DIR..."
cp -R "$PROJECT_DIR"/* "$INSTALL_DIR/"

# Create artifacts directory structure if it doesn't exist
echo "Setting up artifacts directory..."
mkdir -p "$ARTIFACTS_DIR/logs"
mkdir -p "$ARTIFACTS_DIR/db"
mkdir -p "$ARTIFACTS_DIR/reports"

# Set proper ownership and permissions
echo "Setting proper permissions..."
chown -R "$REAL_USER" "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"
chmod -R 777 "$ARTIFACTS_DIR"  # Ensure artifacts directory is writable

# Install Python requirements
echo "Installing Python requirements..."
if command -v pip3 &> /dev/null; then
    # Use pip3 if available
    sudo -u "$REAL_USER" pip3 install -r "$INSTALL_DIR/requirements.txt"
elif command -v pip &> /dev/null; then
    # Fall back to pip if pip3 is not available
    sudo -u "$REAL_USER" pip install -r "$INSTALL_DIR/requirements.txt"
else
    echo "Error: pip is not installed. Please install pip first."
    exit 1
fi

# Create the executable script in /usr/local/bin
echo "Creating executable script..."
cat > "$EXECUTABLE" << EOF
#!/bin/bash
cd /usr/local/share/penetration-testing-toolkit
python3 src/main.py "\$@"
EOF

# Make the script executable
chmod +x "$EXECUTABLE"
chown "$REAL_USER" "$EXECUTABLE"

echo "Installation complete! You can now use the 'pentest' command from anywhere."
echo "To uninstall, run: sudo rm -rf $INSTALL_DIR $EXECUTABLE"
