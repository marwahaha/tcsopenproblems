# TCS Open Problems

A web application for sharing and discussing open problems in Theoretical Computer Science. Users can submit problems, vote, rate (impact/solvability), and comment. Supports Markdown and LaTeX.

## Installation

```bash
# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Running

```bash
python app.py
```

The app will be available at http://localhost:5000

## Features

- User registration and authentication
- Submit open problems with categories
- Markdown and LaTeX support in descriptions
- Upvoting and rating system (impact/solvability)
- Comments on problems
- Admin dashboard for managing content

## Deploying on the server

git pull

then

```
sudo service tcsopenproblems restart
```

If there was a DB change, I like to copy over the database somewhere else just in case.
