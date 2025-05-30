# ---------------------------------------------------------------------------------
import json
import re
import math
import customtkinter as ctk
from tkinter import messagebox
# ---------------------------------------------------------------------------------

# ---------------------------------------------------------------------------------
# opens up the json file which is my results
def result__json():
    try:
        with open("Results.json", "r") as f:
            data = json.load(f)
            return set(data["common_passwords"]), set(data["common_patterns"])
    except FileNotFoundError:
        messagebox.showerror("A error happened,", "Results.json not found. You need to go back and run analyzer script first.")
        return set(), set()

common_passwords, common_patterns = result__json()

# -----------------------------------------------------------------------------------
# calculate entropy which type of character each string has, lower, upper, digits and special characters
def calc__entropy(password):
    all_char_sets = {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"[0-9]", password)),
        "special": bool(re.search(r"[^a-zA-Z0-9]", password))
    }
    N = (26 * all_char_sets["lower"]) + (26 * all_char_sets["upper"]) + (10 * all_char_sets["digits"]) + (32 * all_char_sets["special"]) # the more characters type the more the sum and complexity goes up
    if N == 0:
        return 0
    return len(password) * math.log2(N)

# ------------------------------------------------------------------------------------
# to know if the passwords are in the common passowrds 
def comn__password(password):
    return password in common_passwords

# -------------------------------------------------------------------------------------
# matches input with result json 
def comn__pattern(password):
    return generate_password_mask(password) in common_patterns

# -------------------------------------------------------------------------------------
# finds out the mask of the input password, varies from lower, upper, digit and symbols

def generate_password_mask(password):
    mask = re.sub(r'[a-z]', 'l', password)
    mask = re.sub(r'[A-Z]', 'U', mask)
    mask = re.sub(r'[0-9]', 'd', mask)
    mask = re.sub(r'[^a-zA-Z0-9]', 's', mask)
    return mask
# -------------------------------------------------------------------------------------
# calculates the strength with criterias, the final output will be a score
def passwrd__str(password):
    if len(password) < 8:
        return 0, ["Your password is too short. Use at least 8 characters."]

    length_score = 25 if len(password) >= 16 else 20 if len(password) >= 12 else 8 if calc__entropy(password) > 40 else 5
    lower = bool(re.search(r"[a-z]", password))
    upper = bool(re.search(r"[A-Z]", password))
    digits = bool(re.search(r"[0-9]", password))
    special = bool(re.search(r"[^a-zA-Z0-9]", password))

    character_score = sum([lower, upper, digits, special]) * 6
    if lower and upper and not (digits or special):
        character_score += 4
    if len(password) >= 8 and digits and special:
        character_score += 8
    if len(password) >= 12 and digits and special:
        character_score += 30
    if re.fullmatch(r"[0-9]+", password) or re.fullmatch(r"[a-zA-Z]+", password):
        character_score -= 30

    pattern_penalty = -50 if comn__password(password) or comn__pattern(password) else 0 # gives minus points if it has common pattern and password
    entropy_score = round(min(calc__entropy(password) / 3, 30))

    score = length_score + character_score + entropy_score + pattern_penalty # the final score is all the variables added together
    # used to identify what is missing for feedback 
    missg__type = [cat for cat, check in [ 
        ('lowercase letters', lower),
        ('uppercase letters', upper),
        ('numbers', digits),
        ('special characters', special)
    ] if not check]

    if missg__type:
        score = min(score, 80)

    feedback = []
    if comn__password(password):
        feedback.append("Your password is commonly used. Choose something more unique.") 
    if comn__pattern(password):
        feedback.append("Your password follows a common pattern. Avoid predictable structures.") 
    if missg__type:
        feedback.append(f"To improve security, include: {', '.join(missg__type)}.")  
    if 12 <= len(password) < 16 and not missg__type:
        feedback.append("Strong Password! Want even stronger? Use 16 characters.") 
    elif len(password) >= 16 and not missg__type:
        feedback.append("Wow, now your password is unbreakable!") 

    if not (lower and upper and digits and special):
        score = min(score, 80) 

    return max(0, min(100, score)), feedback 
# ------------------------------------------------------------------------------------------
# GUI that handles the interface and how functioanlity is working with our functions 
def create_gui():
    ctk.set_appearance_mode("dark") # dark mode for the interface
    ctk.set_default_color_theme("blue")

    root = ctk.CTk()
    root.geometry("500x400") 
    root.title("PassProof") 

    frame = ctk.CTkFrame(root, corner_radius=10) 
    frame.pack(pady=20, padx=20, fill="both", expand=True) # pady adds a depth vertically to the outside the frame to make it more soothing, while padx adds the same but for horizontal, fill makes the frame expand on both vert and hors, lastly expand will make extra space when the user expands the window

    title_label = ctk.CTkLabel(frame, text="PassProof - Advanced Password Checker", font=("Arial", 18, "bold")) # make the head title in the program and make fonts etc
    title_label.pack(pady=(10, 5)) # make the tile etc appear within the frame, adds 10 pixels padding above and 5 below

    entry = ctk.CTkEntry(frame, width=350, show="•") # create a text box, while show • hides the character typed
    entry.pack(pady=5) # tells where to place the text widget, which needs to be within the frame in the middle
    def toggle_password_visibility(): 
        if entry.cget('show') == '': # check the value of show, if its empty, the password is visable
            entry.configure(show='•') # we want to change the hiding of passowrds
            toggle_btn.configure(text='Show Password') # make two bottom first Show Password
        else:
            entry.configure(show='') # means to change it when its normally shown password
            toggle_btn.configure(text='Hide Password') # Hide it bottom when the password is visiable


    toggle_btn = ctk.CTkButton(frame, text="Show Password", width=120, command=toggle_password_visibility) # its toggeled when the botton is clicked on
    toggle_btn.pack(pady=(0, 10)) # adds padding to the frame, 0 above and 10 below


    char_label = ctk.CTkLabel(frame, text="Number of Characters: 0", font=("Arial", 12)) # new label to display how many characters that has been typed
    char_label.pack() # have the new label wihtin the frame

    def update_char_count(event=None):
        char_label.configure(text=f"Number of Characters: {len(entry.get())}") # get the length of characters by counting length, it gets updated when typed

    entry.bind("<KeyRelease>", update_char_count) # makes sure the function is updated whenever a key is released 

    password_score_label = ctk.CTkLabel(frame, text="Password Strength: 0/100", font=("Arial", 14)) # new label for password strength from 1-100 in score
    password_score_label.pack(pady=10) # within the frame

    progressbar = ctk.CTkProgressBar(frame, orientation="horizontal") # create a progression bar
    progressbar.set(0) # sets it to 0%
    progressbar.pack(pady=10, fill="x")

    feedback_label = ctk.CTkLabel(frame, text="", wraplength=400, justify="left") # label to show feedback to the user
    feedback_label.pack(pady=10)
# --------------------------------------------------------------------------------------------
# for checking the password strength when the check password button is clicked
    def chck_password():
        password = entry.get() #input string
        score, feedback = passwrd__str(password)   
        progressbar.set(score / 100) #update the progress bar to the score
        password_score_label.configure(text=f"Password Strength: {score}/100") # output the score to the user
        feedback_label.configure(text="\n".join(feedback) if feedback else "Medium password, Try 12 characters :-D") # if there is feedback join them together, if the feedback is empty the then give the message to try 12 character

    check_button = ctk.CTkButton(frame, text="Check Password", command=chck_password) # when the check password is clicked the score and feedback is triggered
    check_button.pack(pady=10)
    

    entry.pack(pady=5)

    

    root.mainloop()

if __name__ == "__main__":
    create_gui()
# --------------------------------------------------------------------------------------------

# PAY ATTENTION! YOU HAVE TO FIRST RUN THE PREPROCESSING SCRIPT FIRST, AND THEN RUN THE ANALYZE_DATA.PY BEFORE RUNNING THIS SCRIPT. IF NOT THEN IT WILL GIVE ERROR WHEN TESTING
# YOU COULD ALWAYS JUST RUN THE PASSPROOFINSTALLER AND RUN THE PROGRAM RIGHTAWAY, BUT IF YOU WANT TO SEE THE PROCESS YOU HAVE TO FOLLOW THE INSTRUCTIONS.
