import pandas as pd
import re
import json
import config  
# ---------------------------------------------------------------------------------------
def msk_passwords(password):
    mask = re.sub(r'[a-z]', 'l', password) # ifcheck password is lower letter, and replace it with l
    mask = re.sub(r'[A-Z]', 'U', mask) # check if the password has upper letters, and place it with letter U
    mask = re.sub(r'[0-9]', 'd', mask) # check if the password contains numbers, and replace it with the letter d,
    mask = re.sub(r'[^a-zA-Z0-9]', 's', mask) # check if the password contains special symbols and replace it with s
    return mask
# ----------------------------------------------------------------------------------------
# ----------------------------------------------------------------------------------------
def analyze_passwords(csv_file):
    df = pd.read_csv(csv_file) # it reads the leaked dataset
    df = df.dropna(subset=["Password"]) # remove the rows that is empty and has no value in the password coloumn
    
    # Find common passwords in dataset
    df["Is_Common"] = df["Password"].isin(config.common_passwords) # compare the two files, the config.py passwords, with the cvs password
    
    df["Length"] = df["Password"].apply(len) # make new column to get the length of the passwords
    df["Mask"] = df["Password"].apply(msk_passwords) # make a new mask to get the structre of password
    
    avg_length = df["Length"].mean() # calculate the average length
    comn__patterns = df["Mask"].value_counts().head(500).index.tolist() # finds the most common pattern, top 50 of them
    comn_passw_found = df["Password"].value_counts().head(500).index.tolist() # finds the most common passwords, top 50 of them
    
    # dictionary to store the values we wwant
    analysis_data = {
        "avg_length": avg_length, 
        "common_patterns": comn__patterns, 
        "common_passwords": comn_passw_found 
    }
    
    with open("Results.json", "w") as f: # summary file for later
        json.dump(analysis_data, f, indent=4)
    
    print("Analysis complete. Data saved to 'Results.json'.")
# ------------------------------------------------------------------------------------------
if __name__ == "__main__":
    analyze_passwords("cleaned_dataset.csv")


