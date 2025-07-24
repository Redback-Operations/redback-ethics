import pandas as pd
import faker as faker
import os

# Function to print the banner for the application
def print_banner():
    print("=" * 63)
    print("         🔎 Redback Dummy Data Generator v1.0")
    print("=" * 63)
    print("\n Welcome to the Redback Dummy Data Generator!")
    print(" This tool generates realistic test files containing")
    print(" synthetic sensitive data for scanner testing purposes.\n")
    print("-" * 63)

# Function to get a valid directory path from the user
def get_valid_path():
    while True:
        path = input("Enter the directory path to save the files (press Enter to save in the project folder): ").strip()
        path = path.strip('"').strip("'")  # Remove surrounding quotes if present
        if not path:  # If no input is provided, use the current directory
            print("No path provided. Files will be saved in the project folder.")
            print("-" * 63)
            return os.getcwd()
        elif os.path.isdir(path):  # Validate the provided path
            print("-" * 63)
            return path
        
        else:
            print("We cannot find that path. Please enter a valid directory or press Enter to use the project folder.")
            

# Function to get the file types the user wants to generate
def get_file_types():
    print(" Please choose the file type(s) to generate:")
    print(" [1] CSV (.csv)")
    print(" [2] JSON (.json)")
    print(" [3] Text (.txt)")
    print(" [4] Word Document (.docx)")
    print(" [5] PDF (.pdf)")
    print(" [6] All of the above")
    while True:
        # Prompt user for input and validate it
        choice = input(" Enter your choice (e.g., 1 or 3,5 or 6): ").strip()
        if choice and all(c in "123456," for c in choice.replace(" ", "")):
            return choice  # Return valid input
        print(" Invalid input. Please enter a valid choice (e.g., 1 or 3,5 or 6).")

# Function to get the sensitivity level of the data
def get_sensitivity_level():
    print("-" * 63)
    print(" Select data sensitivity level:")
    print(" [1] Low (Public or non-sensitive)")
    print(" [2] Medium (Internal-use PII/NPI)")
    print(" [3] High (Critical PII, PHI, Financial, Secrets, Username & Password Combinations)")
    print(" [4] Mixed (Randomised levels)")
    while True:
        # Prompt user for input and validate it
        level = input(" Enter your choice: ").strip()
        if level in {"1", "2", "3", "4"}:
            return level  # Return valid input
        print(" Invalid input. Please enter a number between 1 and 4.")

# Function to get the number of files to generate
def get_number_of_files():
    print("-" * 63)
    while True:
        # Prompt user for input and validate it
        count = input(" Enter number of sample files to generate for each selected category: ").strip()
        if count.isdigit() and int(count) > 0:
            return int(count)  # Return valid input as an integer
        print(" Invalid input. Please enter a positive integer.")

def convert_type_to_string(file_types):
    # Convert the file type numbers to their string representations
    file_type_map = {
        "1": "CSV",
        "2": "JSON",
        "3": "Text",
        "4": "Word Document",
        "5": "PDF",
        "6": "All of the above"
    }
    return [file_type_map.get(ft, ft) for ft in file_types.split(",") if ft in file_type_map]

# Function to print a summary of the user's selections
def print_summary(file_types, sensitivity, count):
    print("-" * 63)
    print(" Summary of your selections:")
    print(f"    - File types selected: {convert_type_to_string(file_types)}")
    print(f"    - Sensitivity level: {sensitivity}")
    print(f"    - Total files: {count}")
    print("-" * 63)

# Main function to handle the console-based user interface
def console_ui():
    print_banner()  # Display the banner
    path = get_valid_path()  # Get a valid directory path from the user
    file_types = get_file_types()  # Get file types from the user
    sensitivity = get_sensitivity_level()  # Get sensitivity level from the user
    count = get_number_of_files()  # Get the number of files to generate
    print_summary(file_types, sensitivity, count)  # Print a summary of the selections
    return path, file_types, sensitivity, count  # Return the collected inputs

def finish_ui():
    print("-" * 63)
    print(" Thank you for using the Redback Dummy Data Generator!")
    print("-" * 63)