# Repost-bot.ps1
Requirements
    1. The image resize function, I got it from https://gist.github.com/someshinyobject/617bf00556bc43af87cd
    2. Windows machine when using the above function, or an alteration to a linux compatible one if you're
       running it on a raspberry pi
    3. A Reddit account with an app registration
 
Version: 0.1.6
    Added an output to a html file for easier invesigation of reposts
    Using folder name as base for subreddit/save location
    Minor changes in variables
Version: 0.1.5:
    Resolved unsuccessfull report
Version: 0.1.0
    Capabilities: This script is used to check NSFW posts and let nudenet determine if it's NSFW.
    If NSFW, lock the post. Can be integrated into the general flair-bot to remove and action automatically but didn't
    get it to run outside of Windows yet.
This script is made to moderate /r/$subname
To use this bot, use the global variables to get started. I'm not a programmer so if the code looks chunky you'll 
know why ;)
I expect you can run multiple instances with the same ClientID and Secret but with different subreddits, the Reddit
rate-limiting could be a factor and is included in the code. It does not look into actions of multiple instances so it 
could be one script is constantly waiting while others keep using the rate that's available. If you want that you'll 
need to use some kind of logic to maintain the sequencing of actions across multiple instances (like an overall management
script.
This script uses the root folder name as it's temporary storage for files and a checklist to see if it's already actioned
a post previously.
    hashedposts.txt - To keep track of posts that had been hashed
    token.txt - Plain text oauth token saving to avoid having a token created at every run (I'm assuming Reddit doesn't like that)
    filehashs.csv - The list of hashed images, based on a 12x12 resize of the original to account for minor variations, the original images are NOT saved in the interest of the original poster. 
    $subname-hashes.log - A Powershell transcript of the log actions, which is also why I use write-host rather than
      write-output
Known issues:
  1. Gallery posts that are spoilered give an error
  2. Videos are not processed at all
  3. Text posts are not included
  4. Imgur or other external images may or may not work, depending on how the image is included in the post
  
Performance?
  Running the script on my laptop (Ryzen 4800H / 16GB memory) doesn't have any noticable effect on performance 
  (even during games like MSFS at ultra resolution).
  Running the script with a limit=100 did have some effect, but it was done in about a minute where the posts 
  has about galleries in about 40% of the posts, going back 10-12 hours (quarter milion members subreddit).
  I run my bot every minute which is fine with the limit=5.
