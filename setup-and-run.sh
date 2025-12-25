#!/bin/bash

# ============================================
# Backend Setup and Run Script
# ============================================
# This script will download (if needed), setup,
# and run the POST Monitor backend server
# ============================================

set -e  # Exit on error

# Configuration
REPO_URL=""  # Add your git repository URL here if using git
PROJECT_DIR="blocker/backend"
BACKEND_DIR="backend"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  POST Monitor Backend Setup & Run${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for required tools
echo -e "${YELLOW}Checking required tools...${NC}"

if ! command_exists python3; then
    echo -e "${RED}Error: python3 is not installed${NC}"
    echo "Please install Python 3.7 or higher"
    exit 1
fi

if ! command_exists pip3; then
    echo -e "${RED}Error: pip3 is not installed${NC}"
    echo "Please install pip3"
    exit 1
fi

echo -e "${GREEN}✓ Python3 and pip3 found${NC}"
echo ""

# Download/Clone backend if not in current directory
if [ ! -f "main.py" ] && [ ! -f "requirements.txt" ]; then
    echo -e "${YELLOW}Backend files not found in current directory${NC}"

    # Check if git URL is configured
    if [ -z "$REPO_URL" ]; then
        echo -e "${RED}Error: Backend not found and REPO_URL not configured${NC}"
        echo ""
        echo "Please either:"
        echo "  1. Run this script from the backend directory, OR"
        echo "  2. Edit this script and set REPO_URL to your git repository"
        echo ""
        echo "Example:"
        echo "  REPO_URL=\"https://github.com/username/repo.git\""
        exit 1
    fi

    # Clone repository
    if command_exists git; then
        echo -e "${BLUE}Cloning repository from $REPO_URL...${NC}"
        git clone "$REPO_URL" temp_clone

        # Move backend files to current directory or navigate to backend
        if [ -d "temp_clone/$BACKEND_DIR" ]; then
            cd "temp_clone/$BACKEND_DIR"
        else
            cd temp_clone
        fi
    else
        echo -e "${RED}Error: git is not installed${NC}"
        echo "Please install git or manually download the backend"
        exit 1
    fi
fi

# Now we should be in the backend directory
if [ ! -f "main.py" ]; then
    echo -e "${RED}Error: main.py not found${NC}"
    echo "Are you in the correct directory?"
    exit 1
fi

echo -e "${GREEN}✓ Backend files found${NC}"
echo ""

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "${BLUE}Creating virtual environment...${NC}"
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi
echo ""

# Activate virtual environment
echo -e "${BLUE}Activating virtual environment...${NC}"
source venv/bin/activate

# Upgrade pip
echo -e "${BLUE}Upgrading pip...${NC}"
pip install --upgrade pip >/dev/null 2>&1
echo ""

# Install dependencies
echo -e "${BLUE}Installing dependencies...${NC}"
pip install -r requirements.txt

echo ""
echo -e "${GREEN}✓ All dependencies installed${NC}"
echo ""

# Display server information
echo -e "${BLUE}============================================${NC}"
echo -e "${GREEN}🚀 Starting POST Monitor Backend Server...${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""
echo -e "${GREEN}Server will start on:${NC}"
echo -e "  • Main: ${BLUE}http://127.0.0.1:8000${NC}"
echo -e "  • API Docs: ${BLUE}http://127.0.0.1:8000/docs${NC}"
echo -e "  • Alternative Docs: ${BLUE}http://127.0.0.1:8000/redoc${NC}"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
echo ""
echo -e "${BLUE}============================================${NC}"
echo ""

# Start the server
python main.py
