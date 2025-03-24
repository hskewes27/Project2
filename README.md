# Project2
BIO Jwks server with sqlite db still errors out a bit hoping to go over it in recitation

Requirements: cryptographt, pyjwt

Description - Practivev2 meets most of flake8s standards besides line character count, comments try to explain thought process/ functionality of the program. Logs are also used to keep track of what is going on in the program. The program can work with or without the proper database file being present at the time and it will populate within the correct directory if it is not there when the program starts up with the correct table formed. The programs main error starts in the server class things seem to make their way to the database fine, but then issues arise when decoding starts.

Testing- So I did have a seperate test suite, but since I was having so many problems with it I barely used it. I opted to use logs within the code to get a good picture of what was happening for my code to not work, but clearly that was not enough.

Some resources I used to code this assignment along with ai prompts
- https://www.youtube.com/watch?v=6faDYCsTXZU
- https://www.youtube.com/watch?v=E-BEOD0EPDA
- https://www.youtube.com/watch?v=phNDrH6GckE I watched this but did not end up using flask
prompts used
- Why am I getting a jwt error?
- How should I got about encoding then decoding a jwt from a sqlite db?
- How should I go about linting a python file?
- What does a flake8 linted program look like?
- What are common jwt errors and their fixes?
