import pandas as pd
import faker as faker
from console_ui import *
from file_generation import *
from scanner_bot.scan_engine import RegexScanner

# Entry point of the script
path, file_types, sensitivity, count = console_ui()

# Change the working directory to the user-provided path, if a path was given
if path != os.getcwd():  # Only change if the path is different from the current directory
    os.chdir(path)

# Create an instance of DummyDataGenerator
generator = DummyDataGenerator(sensitivity)

# Generate files based on user input
generate_selected_files(generator, file_types, count)

# Print a completion message
finish_ui()