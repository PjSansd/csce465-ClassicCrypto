# Part 1:

Set up the environment, and install the following libraries

pip install pyaes
pip install pbkdf2
pip install cryptography

Download or create a "data.json" file that just contains
{"action":"READ","path":"notes.txt"}
put it in the same folder as the program. 

You can run the program with python3 baseline_ctr.py/


# Part 2:

python3 handshake.py

# Part 3: 

python3 secure_record.py

# Part 4: 

be in the hw2 directory, and then use

python3 -m unittest discover -s tests -v
