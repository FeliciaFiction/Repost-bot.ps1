<###
Requirements
    1. The image resize function, I got it from https://gist.github.com/someshinyobject/617bf00556bc43af87cd
    2. Windows machine when using the above function, or an alteration to a linux compatible one if you're
       running it on a raspberry pi
    3. A Reddit account with an app registration
Version: 0.1.7
    Added video to downloads, may not work as expected (or be effective at all) since the file needs a 100% match.
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
could be one script is constantly waiting while others keep using the rate that's available.

This script uses the root folder name as it's temporary storage for files and a checklist to see if it's already actioned
a post previously.
    hashedposts.txt - To keep track of posts that had been hashed
    token.txt - Plain text saving to avoid having a token created at every run (I'm assuming Reddit doesn't like that)
    filehashs.csv - The list of hashed images, based on a 12x12 resize of the original to account for minor variations
    $subname-hashes.log - A Powershell transcript of the log actions, which is also why I use write-host rather than
      write-output

Known issues:
  1. Gallery posts that are spoilered give an error
  2. Videos are not processed
  3. Text posts are not included
  4. Imgur or other external images may or may not work, depending on how the image is included in the post
  
Performance?
  Running the script on my laptop (Ryzen 4800H / 16GB memory) doesn't have any noticable effect on performance 
  (even during games like MSFS at ultra resolution).
  Running the script with a limit=100 did have some effect, but it was done in about a minute where the posts 
  has about galleries in about 40% of the posts, going back 10-12 hours (quarter milion members subreddit).
  I run my bot every minute which is fine with the limit=5.
###>

# Global variables:
$username = ""                                                      # Your Reddit username, or define with a secure vault
$password = ""                                                      # Your Reddit password, or define with a secure vault
$ClientId = ""                                                      # Your Reddit app's client id, or define with a secure vault
$clientsecret = ""                                                  # Your Reddit app's clientsecret, or define with a secure vault
$useragent = "$username's Repost-hasher 0.1.7"                      # Useragent, update version
$subname = $PSScriptRoot | Split-Path -Leaf                         # General subname based on folder name
$apiurl = "https://oauth.reddit.com"                                # API url 
$storage =  $PSScriptRoot                                           # Storage per subreddit
$oauthsubreddit = "https://oauth.reddit.com/r/$subname"             # Oauth URL for subreddit specific operations
$ProgressPreference = 'Silentlycontinue'                            # Do not show invoke-webrequest progress

# Log output
Write-host (get-date) (Start-Transcript $storage\$subname-hashes.log -Append  -UseMinimalHeader)

# Functions
Function New-redditremovalnotice {
    param (
    [Parameter (Mandatory = $True)] [String]$postid,
    [Parameter (Mandatory = $True)] [String]$author,
    [Parameter (Mandatory = $True)] [String]$Removalreason
    )
    
    #Build request-body
    $removalpostbody = @{
    thing_id = $postid
    text = "Dear /u/$author, your post has been removed for the following reason: $Removalreason. 
    This is a bot, If you have questions or concerns about this removal, please [message the moderators](https://www.reddit.com/message/compose?to=/r/$subname&subject=&message=)"
    }
    # Execute request
    Invoke-RestMethod "$apiurl/api/comment" -body $removalpostbody -headers $headers -Method POST -useragent $useragent
    
    # Get removal-comment
    $comments = Invoke-RestMethod https://www.reddit.com/u/$username/.json 
    $comments = $comments.data.children.data
    $modcomment = $comments[0..0].name

    $modcommentbody = @{
        how = 'yes'
        id = $modcomment
        sticky = 'True'
    }
    
    Invoke-RestMethod "$apiurl/api/distinguish" -body $modcommentbody -headers $headers -Method POST -useragent $useragent
    

    # Output log
    Write-Host (Get-date)'Added removal reason for actioned post:' $postid
    # Append post name to actioned list
    } # End of new reddit removal reason

Function Get-reddittoken {
   
    # Build token request
    $credential = "$($ClientId):$($clientsecret)"
    $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credential))
    $basicAuthValue = "Basic $encodedCreds"
    $body = "grant_type=password&username=$username&password=$password"

    # Execute token request
    $token = Invoke-RestMethod -body $body -Headers @{Authorization = $basicAuthValue}  -method post   -useragent "Wauske's flairbot 0.2" -uri 'https://www.reddit.com/api/v1/access_token'
    $bearer = $token.access_token
    $geldigheidtoken = (get-date).AddSeconds(86400)

    # Build Beaerer token and validity output table
    $return = new-object system.data.datatable
        # Adding columns
        [void]$return.Columns.Add("Bearer")
        [void]$return.Columns.Add("geldigheidtoken")

        [void]$return.Rows.Add($bearer,$geldigheidtoken)

    # Output Bearer token and validity 
    return $return

} # Einde get-reddittoken

$token = Import-Csv $storage\token.txt
Write-Host (get-date) 'Imported token with expiry date:' $token.geldigheidtoken

# If token not exists, get one
if ($null -eq $token){
    $token = Get-reddittoken
    $bearer = $token.Bearer
    $geldigheidtoken = $token.geldigheidtoken
    write-host (get-date) 'Succesfully acquired token, valid until' $geldigheidtoken
}

# If token does exist, check validity and renew if expired
if ((get-date) -gt (get-date($token.geldigheidtoken))) {
    $token = Get-reddittoken
    if ([bool]$bearer) { Write-Host (get-date) 'Succesfully acquired token' $bearer[40..43]'..., valid until' $geldigheidtoken}
}


#
# Build headers used for authenticating API request
$bearer = $token.Bearer
$geldigheidtoken = $token.geldigheidtoken
$token | Export-Csv -Path $storage\token.txt #Export-Csv $token   $storage\token.txt
$headers = @{Authorization="Bearer $bearer"}


### Functions
Function Invoke-Marksnsfwpost {
    param (
    [Parameter (Mandatory = $True)] [String]$Postid
    )

    # Code block
    invoke-restmethod -Headers $headers -uri "$apiurl/api/marknsfw" -body @{id = $postid} -UserAgent $useragent -method Post
    write-output (get-date)'Marked post NSFW:'$Postid
} # End function invoke-marknsfwpost

Function New-redditmodnote {
    param (
    [Parameter (Mandatory = $True)] [String]$postid,
    [Parameter (Mandatory = $True)] [String]$link_flair_text,
    [Parameter (Mandatory = $True)] [String]$author,
    [Parameter (Mandatory = $True)] [String]$subreddit_modnote
    )

    #Build request-body
    $modnotebody = @{note = $link_flair_text
    reddit_id = $postid
    subreddit = $subreddit_modnote
    user = $author
    }   
    # Execute request
    Invoke-RestMethod "$apiurl/api/mod/notes" -body $modnotebody -headers $headers -Method POST -useragent $useragent

    # Output log
    Write-Host (Get-date)'Added mod-note for actioned post:' $postid $link_flair_text 
    # Append post name to actioned list
}

Function Lock-redditpost {
    param (
    [Parameter (Mandatory = $True)] [String]$Postid
    )

    # Code block
    invoke-restmethod -Headers $headers -uri "$apiurl/api/lock" -body @{id = $postid} -UserAgent $useragent -method Post
    Write-Host (get-date)"Locked post"$postid
} # End function lock-redditpost

Function Remove-redditpost {
    param (
    [Parameter (Mandatory = $True)] [String]$Postid,
    [Parameter (Mandatory = $True)] [String]$spam
    )

    # Code block
    invoke-restmethod -Headers $headers -uri "$apiurl/api/remove" -body @{id = $postid; spam = $spam} -UserAgent $useragent -method Post
    Write-output (get-date)'Removed post:'  $postid
} # End function Remove-redditpost

Function Invoke-redditban {
    param (
      [Parameter (Mandatory = $True)] [String]$user,
      [Parameter (Mandatory = $True)] [String]$container,
      [Parameter (Mandatory = $True)] [String]$duration,
      [Parameter (Mandatory = $True)] [String]$reason
    )

    # Code block
    $body = @{
      ban_reason=$reason
      ban_message=$reason
      name=$user
      note=$reason
      type="banned"
    }
    if ($duration -ne 'False') {$body += @{duration = $duration} }

    # Perform the ban    
    invoke-restmethod -Headers $headers -uri "$oauthsubreddit/api/friend" -body $body -UserAgent $useragent -method Post

    # Output success
    write-host (get-date)"Banned user: $user" 'for' $reason

    } # End function invoke-redditban

Function invoke-filehash {

    # Code block
    # Resize image to 12x12 to account for minor changes
    Resize-Image -ImagePath $storage\filehash.jpg -Height 12 -Width 12

    # Remove source image
    remove-item $storage\filehash.jpg -Force

    # Hash the resized file
    $hash = Get-FileHash $storage\filehash_resized.jpg

    # Remove resized image
    remove-item $storage\filehash_resized.jpg -force
    
    # Add post url and date to hash-variable for proof later on
    $hash | Add-Member -MemberType NoteProperty  -Name post-date -Value (Get-Date)
    $hash | Add-Member -MemberType NoteProperty  -Name Post-ID -Value ($post.name -replace('t3_','https://www.reddit.com/comments/'))
    $hash | Add-Member -MemberType NoteProperty -Name Author -Value ($post.author)

    return $hash
} # End of invoke-filehash

# Invoke-hashmatch
Function Invoke-hashmatch{
    param (
        [Parameter (Mandatory = $True)] $hash
    )
            
    # Check new against known hashes
    foreach ($knownhash in (Import-Csv $storage\filehashs.csv)){
        if($hash.hash -eq $knownhash.hash){
            # actie als match
            #Remove-redditpost -Postid $post.name
            #New-redditmodnote -postid $post.name -author $post.author -subreddit_modnote $subname -link_flair_text "Filehash confirms suspected repost, reported."
            #Lock-redditpost -Postid $post.name
            write-host (get-date) 'Found a repost:' $hash.'Post-ID' 'and previous post:' $knownhash.'Post-ID'

            # Postid maken zoals reddit verwacht
            $postid = 't3_' + $hash.'Post-ID' -replace('https://www.reddit.com/comments/','')

            # Reportreason opbouwen
            $reportreason = "Found a repost, previous post: " + $knownhash.'Post-ID'

            # Report the post as a repost
            invoke-redditreport -postid $postid -Reportreason $reportreason
            Write-host (get-date) "Invoked reddit report with parameters:  $postid and reason: `"$reportreason`""
            
            # Update the html file presenting known reposts
            import-csv $storage\filehashs.csv | Group-Object hash | Where-Object {$_.count -gt 1} | `
                Select-Object -ExpandProperty Group |  Select-Object Post-date, author, hash | ConvertTo-Html > 'G:\Mijn Drive\_Temp\crossdressing\reposters.html'
            } # Einde if hash -eq known hash
        } # Einde foreach known hash
        # Add hash to known hashes
        $hash | Export-Csv $storage\filehashs.csv -Append
} # End invoke-hashmatch

Function Invoke-Redditreport {
    param(
        [Parameter (Mandatory = $True)] [String]$postid,
        [Parameter (Mandatory = $True)] [String]$Reportreason
    )

    # Opbouwen body
    $body = @{
        other_reason = $Reportreason
        thing_id = $postid
    }

    $result = invoke-restmethod -uri "$apiurl/api/report" -Body $body -Headers $headers -UserAgent $useragent -Method POST
    write-host (get-date) "Reported post with reason: $Reportreason"
    
    Write-Host (get-date) "Report succesful:" $result.success
    
} # End of invoke-hashmatch

## End functions

# Start main script

# Splat the frequently used vars to shorten commands
$iwrsplat = @{
    Headers = $headers
    Useragent = $useragent
}

$iwr = Invoke-WebRequest -uri $oauthsubreddit/new?limit=5 @iwrsplat
$posts = $iwr.Content | ConvertFrom-Json

# Check rate limit status
Write-Host (get-date) "Remaining rate limit: $($iwr.Headers.'x-ratelimit-remaining')"
if ($iwr.Headers.'x-ratelimit-remaining'.split('.')[0] -lt 10) { start-sleep -Seconds [int]$iwr.Headers.'x-ratelimit-reset'[0]}


# Extract interesting bits
$posts = $posts.data.children.data

# Log downloaded posts
write-host (get-date) 'Downloaded' $posts.Count 'posts, checking for unknown posts'

# Filter out users not in repost-checklist
## End functions

# Start main script

# Splat the frequently used vars to shorten commands
$iwrsplat = @{
    Headers = $headers
    Useragent = $useragent
}

$iwr = Invoke-WebRequest -uri $oauthsubreddit/new?limit=5 @iwrsplat
$posts = $iwr.Content | ConvertFrom-Json

# Check rate limit status
Write-Host (get-date) "Remaining rate limit: $($iwr.Headers.'x-ratelimit-remaining')"
if ($iwr.Headers.'x-ratelimit-remaining'.split('.')[0] -lt 10) { start-sleep -Seconds [int]$iwr.Headers.'x-ratelimit-reset'[0]}


# Extract interesting bits
$posts = $posts.data.children.data

# Log downloaded posts
write-host (get-date) 'Downloaded' $posts.Count 'posts, checking for unknown posts'

# Loop through posts and download images/videos
foreach ($post in $posts){
    if ($post.name -notin (Get-Content $storage\hashedposts.txt)){
        # New post double beep
        [console]::beep(500,300);[console]::beep(500,300)
         
        $filetypes = '.jpg', '.bmp', '.png', '.gif', 'jpeg', 'webp'

        # Download source image (assuming non-gallery type post)
        if ($post.url.Substring($post.url.length-4) -in $filetypes){

            # Log output unknown post
            Write-host (get-date) 'Found a new post, downloading image'
            
            # Download image to generic filename
            try{
                Invoke-WebRequest -Uri $post.url -OutFile $storage\filehash.jpg -ErrorVariable downloaderror -ErrorAction SilentlyContinue
            }
            catch{Write-Host (get-date 'Error downloading post, dumping json for debug' $post) }

            # Check for download-errors
            if ($downloaderror) { write-host (get-date) 'Could not download image' $post.url
            }
            Remove-Variable downloaderror -ErrorAction SilentlyContinue

            # Hash the image
            $hash = invoke-filehash

            # Check the hash against known list of hashes
            invoke-hashmatch $hash
            
            # Remove temporary files
            remove-item $storage\filehash.jpg -Force
            remove-item $storage\filehash_resized.jpg -Force

            # Clear the hash variable to prevent contamination
            clear-variable hash
        } # End if image of .jpg/png/gif

        # For gallery type posts (only first image)
        elseif ($post.url -match 'gallery') {
            write-host (get-date) 'Found new gallery post, downloading images'
            
            # Get gallery details
            $gallery = $post.gallery_data.items.media_id
            
            # Get gallery images
            foreach ($image in $gallery){
                if (($post.media_metadata | out-string) -match 'm=image/gif'){$extension = '.gif'}
                if (($post.media_metadata | out-string) -match 'm=image/png'){$extension = '.png'}
                if (($post.media_metadata | out-string) -match 'm=image/jpg'){$extension = '.jpg'}
                Invoke-WebRequest -uri "https://i.redd.it/$image$extension" -OutFile $storage\filehash.jpg -ErrorVariable downloaderror -ErrorAction SilentlyContinue
                
                # Check for download errors
                if ($downloaderror) { write-host (get-date) 'Could not download image' $post.url}
                Remove-Variable downloaderror -ErrorAction SilentlyContinue

                # Get hash for the downloaded image
                $hash = invoke-filehash

                # Check hash against known hashes
                invoke-hashmatch $hash

                # Clear the hash variable to prevent contamination
                Clear-Variable hash
            } # End foreach image in gallery
        } # End if gallery type

        ## Video posts
        if ($post.is_video -eq 'true'){

            $iwrparams = @{
                Headers = @{Authorization = 'Bearer ' + $bearer}
                Useragent = $useragent
                Outfile =  "$storage\filehash.vid"
                ErrorVariable = 'downloaderror'
                ErrorAction = 'SilentlyContinue'
            }
            
            # Use youtube DL to download video because dash issues
            $json = C:\Youtube-dl\youtube-dl.exe -F $post.media.reddit_video.scrubber_media_url --write-info-json
            $streamtype = (($json | Where-Object {$_ -match 'hls' -and $_ -notmatch 'audio'})[0] -split(" "))[0]
            c:\youtube-dl\youtube-dl.exe -f $streamtype $post.media.reddit_video.scrubber_media_url -o $storage\filehash.vid -q
            
            #check download
            if (Test-Path $storage\filehash.vid){
                Write-host (get-date) "Succesfully downloaded video from $($post.url)"
            }
                
            
            # Check for download errors
            if ($downloaderror) { write-host (get-date) 'Could not download file' $post.url}
            Remove-Variable downloaderror -ErrorAction SilentlyContinue

            # Get hash for the downloaded image
            $hash = get-filehash $iwrparams.Outfile
            
            # Add post url and date to hash-variable for proof later on
            $hash | Add-Member -MemberType NoteProperty  -Name post-date -Value (Get-Date)
            $hash | Add-Member -MemberType NoteProperty  -Name post-created -Value $post.created
            $hash | Add-Member -MemberType NoteProperty  -Name Post-ID -Value ($post.name -replace('t3_','https://www.reddit.com/comments/'))
            $hash | Add-Member -MemberType NoteProperty -Name Author -Value ($post.author)

            # Check hash against known hashes
            invoke-hashmatch $hash

            # Remove video file
            remove-item $storage\filehash.vid

            # Clear the hash variable to prevent contamination
            Clear-Variable hash
        } # End if video post

        # Add posts to hashed posts
        $post.name | Out-File $storage\hashedposts.txt -Append
        Write-host (get-date) 'Post' $post.name 'added to known posts'
    } # Einde If post notin known posts
}


# Log output finished
Write-host (get-date) 'All done, exiting'

# Clean up log
$time = (Get-date) | Select-Object hour, minute
if ($time.hour -eq 12 -and $time.minute -eq 20) { 
    Write-host (get-date) 'Cleaning up logfile'
    $logcontent = Get-Content $storage\crossdressing-hashes.log -last 10000
    $logcontent | Set-Content $storage\crossdressing-hashes.log }
Write-host (get-date) (Stop-transcript)



# Loop through posts and download images
foreach ($post in $posts){
    if ($post.name -notin (Get-Content $storage\hashedposts.txt)){
        # New post double beep
        [console]::beep(500,300);[console]::beep(500,300)
         
        $filetypes = '.jpg', '.bmp', '.png', '.gif', 'jpeg', 'webp'

        # Download source image (assuming non-gallery type post)
        if ($post.url.Substring($post.url.length-4) -in $filetypes){

            # Log output unknown post
            Write-host (get-date) 'Found a new post, downloading image'
            
            # Download image to generic filename
            try{
                Invoke-WebRequest -Uri $post.url -OutFile $storage\filehash.jpg -ErrorVariable downloaderror -ErrorAction SilentlyContinue
            }
            catch{Write-Host (get-date 'Error downloading post, dumping json for debug' $post) }

            # Check for download-errors
            if ($downloaderror) { write-host (get-date) 'Could not download image' $post.url
            }
            Remove-Variable downloaderror -ErrorAction SilentlyContinue

            # Hash the image
            $hash = invoke-filehash

            # Check the hash against known list of hashes
            invoke-hashmatch $hash
            
            # Remove temporary files
            remove-item $storage\filehash.jpg -Force
            remove-item $storage\filehash_resized.jpg -Force

            # Clear the hash variable to prevent contamination
            clear-variable hash
        } # End if image of .jpg/png/gif

        # For gallery type posts (only first image)
        elseif ($post.url -match 'gallery') {
            write-host (get-date) 'Found new gallery post, downloading images'
            
            # Get gallery details
            $gallery = $post.gallery_data.items.media_id
            
            # Get gallery images
            foreach ($image in $gallery){
                if (($post.media_metadata | out-string) -match 'm=image/gif'){$extension = '.gif'}
                if (($post.media_metadata | out-string) -match 'm=image/png'){$extension = '.png'}
                if (($post.media_metadata | out-string) -match 'm=image/jpg'){$extension = '.jpg'}
                Invoke-WebRequest -uri "https://i.redd.it/$image$extension" -OutFile $storage\filehash.jpg -ErrorVariable downloaderror -ErrorAction SilentlyContinue
                
                # Check for download errors
                if ($downloaderror) { write-host (get-date) 'Could not download image' $post.url}
                Remove-Variable downloaderror -ErrorAction SilentlyContinue

                # Get hash for the downloaded image
                $hash = invoke-filehash

                # Check hash against known hashes
                invoke-hashmatch $hash

                # Clear the hash variable to prevent contamination
                Clear-Variable hash
            } # End foreach image in gallery
        } # End if gallery type

        ## Video posts
        if ($post.is_video -eq 'true'){

            $iwrparams = @{
                Headers = @{Authorization = 'Bearer ' + $bearer}
                Useragent = $useragent
                Outfile =  "$storage\filehash.vid"
                ErrorVariable = 'downloaderror'
                ErrorAction = 'SilentlyContinue'
            }
            
            # Use youtube DL to download video because dash issues
            $json = C:\Youtube-dl\youtube-dl.exe -F $post.media.reddit_video.scrubber_media_url --write-info-json
            $streamtype = (($json | Where-Object {$_ -match 'hls' -and $_ -notmatch 'audio'})[0] -split(" "))[0]
            c:\youtube-dl\youtube-dl.exe -f $streamtype $post.media.reddit_video.scrubber_media_url -o $storage\filehash.vid -q
            
            #check download
            if (Test-Path $storage\filehash.vid){
                Write-host (get-date) "Succesfully downloaded video from $($post.url)"
            }
                
            
            # Check for download errors
            if ($downloaderror) { write-host (get-date) 'Could not download file' $post.url}
            Remove-Variable downloaderror -ErrorAction SilentlyContinue

            # Get hash for the downloaded image
            $hash = get-filehash $iwrparams.Outfile
            
            # Add post url and date to hash-variable for proof later on
            $hash | Add-Member -MemberType NoteProperty  -Name post-date -Value (Get-Date)
            $hash | Add-Member -MemberType NoteProperty  -Name post-created -Value $post.created
            $hash | Add-Member -MemberType NoteProperty  -Name Post-ID -Value ($post.name -replace('t3_','https://www.reddit.com/comments/'))
            $hash | Add-Member -MemberType NoteProperty -Name Author -Value ($post.author)

            # Check hash against known hashes
            invoke-hashmatch $hash

            # Remove video file
            remove-item $storage\filehash.vid

            # Clear the hash variable to prevent contamination
            Clear-Variable hash
        } # End if video post

        # Add posts to hashed posts
        $post.name | Out-File $storage\hashedposts.txt -Append
        Write-host (get-date) 'Post' $post.name 'added to known posts'
    } # Einde If post notin known posts
}


# Log output finished
Write-host (get-date) 'All done, exiting'

# Clean up log
$time = (Get-date) | Select-Object hour, minute
if ($time.hour -eq 12 -and $time.minute -eq 20) { 
    Write-host (get-date) 'Cleaning up logfile'
    $logcontent = Get-Content $storage\crossdressing-hashes.log -last 10000
    $logcontent | Set-Content $storage\crossdressing-hashes.log }
Write-host (get-date) (Stop-transcript)

