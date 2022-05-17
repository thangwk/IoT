# this is the main program
#set folder that you want to save the xml files to
folder = directory
#step 1: load xml files into folder from outlook email
load_data(folder)

# Optional. Change to directory that you want to save the results at
# os.chdir()

# step 2: convert xml files to and aggregate all into a single csv
df = xml_to_csv(folder, output.csv)

# step 3: do groupby to get highest packets and highest alerts based on IP
highest_packet, highest_alert = IP_address_grouping(df)

# Optional. Change to directory that you want to save the results at
# os.chdir()

# step 4: check if IP belongs to SG
SG_highest_packet = match_SG_IP(highest_packet, "SG_highest_packet_matched")
SG_highest_alert = match_SG_IP(highest_alert, "SG_highest_alert_matched")