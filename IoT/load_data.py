import os

import win32com.client

import system

def load_data(output_directory):
    outlook = win32com.client.Dispatch('outlook.application')
    mapi = outlook.GetNameSpace("MAPI")

    # inbox = mapi.Folders(1).Folders('Inbox')
    inbox = mapi.Folders(3).Folders('Inbox')
    messages = inbox.items
    messages = messages.Sort('[ReceivedTime', True)

    outputdir = output_directory
    no_of_msg = len(list(messages))
    try:
        count = 0
        for message in list(messages):
            try:
                count += 1
                for attachment in message.Attachments:
                    attachment.SaveAsFile(os.path.join(outputdir, attachment.FileName))
                    system("cls")
                    print("{} out of {} done".format(count,no_of_msg))
            except Exception as e:
                print("error when saving attachment" + str(e))

