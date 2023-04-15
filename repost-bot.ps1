<###
Version: 0.2.1: 
    Optimizing the search through knownhashes, went from 3.2 seconds per check to 60 milliseconds.
Version: 0.2.0:
    Added option for finding posts since last run
Version: 0.1.8
    Reworking script to run from a single management instance. It will check the latest post and use that
    to find newer posts at the next run.
Version: 0.1.7
    Added QR code recognition, trialing effectiveness
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

This script also uses several files in e:\temp, rename these if you're running multiple instances
    actionedposts.txt - To keep track of posts that had a mod-not added (to prevent doubles after a reboot)
    actionedNSFWposts.txt - To keep track of posts that had been locked as NSFW (to prevent duplicate actions after a reboot)
    flairs.csv - A known list of flairs and the resulting action parameters (not all parameters have been implemented yet)
    pass.txt - Your Reddit password in plain text (yes, I know this is unsafe)
###>

param([string]$subname)

# Global variables:
$username = ""                                                      # Your Reddit username
$useragent = "$username's Repost-hasher 0.2.0"                      # Useragent, update version
$subname = "crossdressing"                                          # General subname based on folder name
$apiurl = "https://oauth.reddit.com"                                # API url 
$storage =  "E:\Temp\$subname\"                                        # Storage per subreddit
$oauthsubreddit = "https://oauth.reddit.com/r/$subname"             # Oauth URL for subreddit specific operations
$ProgressPreference = 'Silentlycontinue'                            # Do not show invoke-webrequest progress

# Log output
Write-host (get-date) (Start-Transcript $storage\$subname-hashes.log -Append  -UseMinimalHeader)

# Build authorizations
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
    # API values for authentication
    $ClientId = ""
    $clientsecret = ""
    $password = ""
    
    # Build token request
    $credential = "$($ClientId):$($clientsecret)"
    $encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($credential))
    $basicAuthValue = "Basic $encodedCreds"
    $body = "grant_type=password&username=$username&password=$password"

    # Execute token request
    $token = Invoke-RestMethod -body $body -Headers @{Authorization = $basicAuthValue}  -method post   -useragent $useragent -uri 'https://www.reddit.com/api/v1/access_token'
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
$token | Export-Csv -Path $storage\token.txt 
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
    if (Test-Path $storage\filehash.jpg){
        Resize-Image -ImagePath $storage\filehash.jpg -Height 12 -Width 12
        
        # Hash the resized file
        $hash = Get-FileHash $storage\filehash_resized.jpg
    }

  
    # Add post url and date to hash-variable for proof later on
    $hash | Add-Member -MemberType NoteProperty  -Name post-date -Value (Get-Date)
    $hash | Add-Member -MemberType NoteProperty  -Name post-created -Value $post.created
    $hash | Add-Member -MemberType NoteProperty  -Name Post-ID -Value ($post.name -replace('t3_','https://www.reddit.com/comments/'))
    $hash | Add-Member -MemberType NoteProperty -Name Author -Value ($post.author)

    return $hash

} # End of invoke-filehash

Function Invoke-hashmatch{
    param (
        [Parameter (Mandatory = $True)] $hash
    )
           
    # Read all known hashes
    $results = Select-String $hash.hash $storage\filehashs.csv | Select-Object Line -First 1
    if ($results){
        $knownhash = $results.line | convertfrom-csv -Header ((Get-Content $storage\filehashs.csv | Select-Object -First 1).Split(',') -replace("`"",""))
    }

    # If linenumber not -1, execute repost report
    if ([bool]$knownhash){ 
        # Postid maken zoals reddit verwacht
        $postid = 't3_' + $hash.'Post-ID' -replace('https://www.reddit.com/comments/','')

        # Timestamp als rekenbare variabele maken            
        $created = [double]$knownhash.'post-created'

        if ($post.created -lt $created + 600 -and $created -ne 0){
            # Probabble duplicate post
            write-host (get-date) 'Found a probable duplicate repost:' $hash.'Post-ID' 'and previous post:' $knownhash.'Post-ID'

            #invoke-redditreport -postid $postid -Reportreason $reportreason
            Write-host (get-date) 'Repost is less than 10 minutes after the original, skipping report.'    
        }
        else {

            # Check previous post
            $previousposturl = ($knownhash.'post-id' -replace("www.","oauth.")) + ".json"

            # Build splat for getting previous post details
            $previouspostsplat = @{
                uri       = $previousposturl
                Useragent = $useragent 
                Headers   = $headers
            }

            # Read the data from Reddit
            $previouspost = Invoke-RestMethod @previouspostsplat

            # Extract the post details
            $previouspost = $previouspost.data.children.data[0]

            if ($previouspost.removed -eq 'True' -and $previouspost.removed_by_category -eq 'moderator'){
                Write-host (get-date) "Previous post removed by mod: $($knownhash.'Post-id')"
                $reportreason = "Repost, previous post removed by mod: " + $knownhash.'post-date'+' ' + $knownhash.'Post-ID'
            }
            elseif($previouspost.removed -match 'False' -and $previouspost.removed_by_category -match 'deleted'){
                Write-host (get-date) "Post removed by user: $($knownhash.'Post-id')"
                $reportreason = "Repost, previous post removed by user: " + $knownhash.'post-date'+' ' + $knownhash.'Post-ID'
            }
            elseif($previouspost.removed -eq 'False' -and $previouspost.removed_by_category -eq ''){
                Write-host (get-date) "Repost, original still online: $($knownhash.'Post-id')"
                $reportreason = "Repost, original still online: " + $knownhash.'post-date'+' ' + $knownhash.'Post-ID'
            }
            elseif($previouspost.author -notmatch 'deleted' -and $previouspost.removed -match 'False'){
                Write-host (get-date) "Original still online: $($knownhash.'Post-id')"
                $reportreason = "Repost, original still online: " + $knownhash.'post-date'+' ' + $knownhash.'Post-ID'
            }
            elseif($previouspost.author -match 'deleted' -and $previouspost.removed -match 'False'){
                Write-host (get-date) "Author deleted account: $($knownhash.'Post-id')"
                $reportreason = "Repost, user deleted account: " + $knownhash.'post-date'+' ' + $knownhash.'Post-ID'
            }
            else{
                Write-host (get-date) "Post status unknown: $($knownhash.'Post-id')"
                $reportreason = "Repost, reason unknown: " + $knownhash.'post-date'+' ' + $knownhash.'Post-ID'
            }

            # Reportreason opbouwen
            [console]::beep(500,800)
            
            # Log output
            write-host (get-date) 'Found a repost:' $hash.'Post-ID' 'and previous post:' $knownhash.'Post-ID'

            # Report the post as a repost
            invoke-redditreport -postid $postid -Reportreason $reportreason
       
        }

        } # Einde if regelnummer niet -1

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
    
}

## Image-resize function
<#
.SYNOPSIS
   Resize an image
.DESCRIPTION
   Resize an image based on a new given height or width or a single dimension and a maintain ratio flag. 
   The execution of this CmdLet creates a new file named "OriginalName_resized" and maintains the original
   file extension
.PARAMETER Width
   The new width of the image. Can be given alone with the MaintainRatio flag
.PARAMETER Height
   The new height of the image. Can be given alone with the MaintainRatio flag
.PARAMETER ImagePath
   The path to the image being resized
.PARAMETER MaintainRatio
   Maintain the ratio of the image by setting either width or height. Setting both width and height and also this parameter
   results in an error
.PARAMETER Percentage
   Resize the image *to* the size given in this parameter. It's imperative to know that this does not resize by the percentage but to the percentage of
   the image.
.PARAMETER SmoothingMode
   Sets the smoothing mode. Default is HighQuality.
.PARAMETER InterpolationMode
   Sets the interpolation mode. Default is HighQualityBicubic.
.PARAMETER PixelOffsetMode
   Sets the pixel offset mode. Default is HighQuality.
.EXAMPLE
   Resize-Image -Height 45 -Width 45 -ImagePath "Path/to/image.jpg"
.EXAMPLE
   Resize-Image -Height 45 -MaintainRatio -ImagePath "Path/to/image.jpg"
.EXAMPLE
   #Resize to 50% of the given image
   Resize-Image -Percentage 50 -ImagePath "Path/to/image.jpg"
.NOTES
   Written By: 
   Christopher Walker
#>
Function Resize-Image() {
    [CmdLetBinding(
        SupportsShouldProcess=$true, 
        PositionalBinding=$false,
        ConfirmImpact="Medium",
        DefaultParameterSetName="Absolute"
    )]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateScript({
            $_ | ForEach-Object {
                Test-Path $_
            }
        })][String[]]$ImagePath,
        [Parameter(Mandatory=$False)][Switch]$MaintainRatio,
        [Parameter(Mandatory=$False, ParameterSetName="Absolute")][Int]$Height,
        [Parameter(Mandatory=$False, ParameterSetName="Absolute")][Int]$Width,
        [Parameter(Mandatory=$False, ParameterSetName="Percent")][Double]$Percentage,
        [Parameter(Mandatory=$False)][System.Drawing.Drawing2D.SmoothingMode]$SmoothingMode = "HighQuality",
        [Parameter(Mandatory=$False)][System.Drawing.Drawing2D.InterpolationMode]$InterpolationMode = "HighQualityBicubic",
        [Parameter(Mandatory=$False)][System.Drawing.Drawing2D.PixelOffsetMode]$PixelOffsetMode = "HighQuality",
        [Parameter(Mandatory=$False)][String]$NameModifier = "resized"
    )
    Begin {
        If ($Width -and $Height -and $MaintainRatio) {
            Throw "Absolute Width and Height cannot be given with the MaintainRatio parameter."
        }
 
        If (($Width -xor $Height) -and (-not $MaintainRatio)) {
            Throw "MaintainRatio must be set with incomplete size parameters (Missing height or width without MaintainRatio)"
        }
 
        If ($Percentage -and $MaintainRatio) {
            Write-Warning "The MaintainRatio flag while using the Percentage parameter does nothing"
        }
    }
    Process {
        ForEach ($Image in $ImagePath) {
            $Path = (Resolve-Path $Image).Path
            $Dot = $Path.LastIndexOf(".")

            #Add name modifier (OriginalName_{$NameModifier}.jpg)
            $OutputPath = $Path.Substring(0,$Dot) + "_" + $NameModifier + $Path.Substring($Dot,$Path.Length - $Dot)
            
            $OldImage = New-Object -TypeName System.Drawing.Bitmap -ArgumentList $Path
            # Grab these for use in calculations below. 
            $OldHeight = $OldImage.Height
            $OldWidth = $OldImage.Width
 
            If ($MaintainRatio) {
                $OldHeight = $OldImage.Height
                $OldWidth = $OldImage.Width
                If ($Height) {
                    $Width = $OldWidth / $OldHeight * $Height
                }
                If ($Width) {
                    $Height = $OldHeight / $OldWidth * $Width
                }
            }
 
            If ($Percentage) {
                $Product = ($Percentage / 100)
                $Height = $OldHeight * $Product
                $Width = $OldWidth * $Product
            }

            $Bitmap = New-Object -TypeName System.Drawing.Bitmap -ArgumentList $Width, $Height
            $NewImage = [System.Drawing.Graphics]::FromImage($Bitmap)
             
            #Retrieving the best quality possible
            $NewImage.SmoothingMode = $SmoothingMode
            $NewImage.InterpolationMode = $InterpolationMode
            $NewImage.PixelOffsetMode = $PixelOffsetMode
            $NewImage.DrawImage($OldImage, $(New-Object -TypeName System.Drawing.Rectangle -ArgumentList 0, 0, $Width, $Height))

            If ($PSCmdlet.ShouldProcess("Resized image based on $Path", "save to $OutputPath")) {
                $Bitmap.Save($OutputPath)
            }
            
            $Bitmap.Dispose()
            $NewImage.Dispose()
            $OldImage.Dispose()
        }
    }
}
## End resize-image function

## End functions

# Start main script

# Splat the frequently used vars to shorten commands
$iwrsplat = @{
    Headers = $headers
    Useragent = $useragent
}

$iwr = Invoke-WebRequest -uri "$oauthsubreddit/new?limit=5" @iwrsplat
$posts = $iwr.Content | ConvertFrom-Json

# Check rate limit status
Write-Host (get-date) "Remaining rate limit: $($iwr.Headers.'x-ratelimit-remaining')"
if ($iwr.Headers.'x-ratelimit-remaining'.split('.')[0] -lt 10) { start-sleep -Seconds [int]$iwr.Headers.'x-ratelimit-reset'[0]}


# Extract interesting bits
$posts = $posts.data.children.data

if ($posts.count -eq 0){ 
    Write-host (get-date) "No new posts, aborting"

    break 
}

# Log downloaded posts
write-host (get-date) 'Downloaded' $posts.Count 'posts, checking for unknown posts'

# Filter out users not in repost-checklist
#$posts = $posts | where {$_.author -in $users}

# Loop through posts and download images
foreach ($post in $posts){
    # Output for queue
    if (!(test-path "$storage\queue\$($post.id).json")){ $post | ConvertTo-Json -Depth 10 | Out-File $storage\queue\$($post.id).json}

    # Remove previous image if it still exists
    if (test-path $storage\filehash.jpg){remove-item $storage\filehash.jpg -Force -Verbose}
    if (test-path $storage\filehash_resized.jpg){remove-item $storage\filehash_resized.jpg -Force -Verbose}

    if ($post.name -notin (Get-Content $storage\hashedposts.txt -Tail 105 )){
        # New post double beep
        Write-host (get-date) 'Post NSFW status:' $post.over_18
        if($post.over_18 -match 'True'){[console]::beep(500,300);[console]::beep(500,300)}
         
        $filetypes = '.jpg', '.bmp', '.png', '.gif', 'jpeg', 'webp'

        # Download source image (assuming non-gallery type post)
        if ($post.url.Substring($post.url.length-4) -in $filetypes){

            # Log output unknown post
            Write-host (get-date) "Found a new post by $($post.author), downloading image"
            
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
            while (Test-Path $storage\filehash.jpg){   remove-item $storage\filehash.jpg -Force -Verbose }
            while (Test-Path $storage\filehash_resized.jpg){   remove-item $storage\filehash_resized.jpg -Force -Verbose }

            # Clear the hash variable to prevent contamination
            clear-variable hash
        } # End if image of .jpg/png/gif

        # For gallery type posts (only first image)
        elseif ($post.url -match 'gallery') {
            write-host (get-date) "Found new gallery post by $($post.author), downloading images"
            
            # Get gallery details
            $gallery = $post.gallery_data.items.media_id
            
            # Get gallery images
            foreach ($image in $gallery){
                # Remove file if exists (loop until completed)
                while (test-path $storage\filehash.jpg){
                    remove-item $storage\filehash.jpg -Force -Verbose
                }
                while (test-path $storage\filehash_resized.jpg){
                    remove-item $storage\filehash_resized.jpg -Force
                }
            
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
            # Output
            Write-Host (get-date) "Found a new video post by $($post.author), downloading video"

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
            while (Test-Path $storage\filehash.vid) {remove-item $storage\filehash.vid -force -verbose}

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
Write-host (get-date) (Stop-transcript)

# Clean up log
$time = (Get-date) | Select-Object hour, minute
if ($time.hour -eq 12 -and $time.minute -eq 20) { 
    Write-host (get-date) 'Cleaning up logfile'
    $logcontent = Get-Content $storage\crossdressing-hashes.log -last 10000
    remove-item $storage\crossdressing-hashes.log -Force
    $logcontent | Set-Content $storage\crossdressing-hashes.log }


# Create a backup copy of the file hashes at midnight
if ((get-date -format "HHmm") -eq 0600){
    $date = Get-Date -Format('yyyyMMdd')
    Copy-Item $storage\filehashs.csv -Destination "$storage\$date - filehash.csv"
}
