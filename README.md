Requirements
 - Python 3.10 or higher
 - pip

1. INSTALL DEPENDENCIES 
  - pip install cryptography PyJWT pytest pytest-cov
# HOW TO RUN
 - Start server "python server.py" in a terminal
 - In a seperate terminal run "pytest --cov=server --cov-report=term-missing" to see blackbox testing
# GRADEBOT
 -  to run grade bot run the command "gradebot.exe project-2 --run="python server.py" with the gradebot files in the same directory
