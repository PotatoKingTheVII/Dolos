<br/>
<p align="center">
  <a href="https://github.com/PotatoKingTheVII/Dolos#gh-light-mode-only" gh-light-mode-only>
    <img src="https://i.imgur.com/35jTSXO.png#gh-light-mode-only" alt="Logo" width="500px">
  </a>

  <a href="https://github.com/PotatoKingTheVII/Dolos#gh-dark-mode-only" gh-light-mode-only>
    <img src="https://i.imgur.com/ZZF4H9C.png#gh-dark-mode-only" alt="Logo" width="500px">
  </a>

  <h3 align="center">PNG Image Steganography</h3>

  <p align="center">
    Intelligently embed payloads into PNG images
  </p>
</p>


## Table Of Contents

* [Overview](#overview--features)
* [Technical Info](#technical)
* [Usage](#usage)
  * [Requirements](#requirements)


## Overview + Features

Most PNG LSB steganography programs embed their payload in a predictable and obvious fashion. Be that along rows/columns, or sequentially in any fixed pattern throughout the image. Even in noisy images this makes detection trivial:

<br>

![Traditional embedding after increasing contrast](https://i.imgur.com/0KsF0ap.png)
*Traditional embedding after increasing contrast*

<br>

Dolos instead embeds data in a random pattern and only in pixels that don't stand out if their LSB is altered, making detection much harder and excelling in difficult situations with little noise/detail to hide payloads. After increasing contrast as before we can't see an obvious payload, and it's only looking at the difference between the original image the edits become apparent:

![enter image description here](https://i.imgur.com/cDHWg2g.png)
*Left: same contrast + payload as before but with Dolos. Right: difference with original file showing altered LSB*

Dolos has only selected pixels that wouldn't stand out (e.g. no pixels in the middle of letters with solid areas of white were chosen). Channels can either be treated together (as above) with the -g option to avoid situations where only embedded pixels would not be greyscale, or separately to maximise capacity with each channel having a separate distribution best suiting its situation.

<br>

**Dolos provides:**
 - Algorithm to avoid homogenous areas, steganography only visible with comparison of original image
 - AES256 GCM providing encryption (Optional password) and integrity authentication
 - Compression to reduce payload footprint
 - Randomised salt resulting in different footprints each subsequent embedding, even with same parameters

<br>

## Technical
The general flow of Dolos is:

 1. Determine eligible pixels for carrying data<sup>[1]</sup>
 2. Shuffle eligible pixel writing order using key derived from hardcoded salt (Using either default/user input password) and embed a new random 16 byte salt<sup>[2]</sup>
3. Using that random salt we derive a new key and shuffle the order of rest of the eligible pixels
4. Payload is compressed, encrypted (Using the key above), and written as: [GCM_auth_tag, AES(`zlib(4-byte-payload-length, null terminated filename, payload)`)]


 - [1]: There are 2 checks for an eligible pixel. Firstly, no neighbouring
   pixels in a 3x3 area must have the same value to avoid homogenous
   areas. Secondly, the first requirement must also be true after
   flipping the last bit of the pixel. This has the effect that even
   after embedding a payload, the pixel will still be considered
   eligible. This is useful on the extraction side allowing the same
   algorithm to be used to discover the payload instead of remembering
   where the edited pixels are somehow.

 - [2]: While this step seems odd at first glance the general idea of using
   an IV with steganography creates a chicken and egg like situation
   where the IV is fundamentally public, while steganography is
   fundamentally private. This setup provides a compromise where a fixed
   known salt derives a "bootstrapping" key which determines the
   shuffled order of only the first 16 bytes which carry the actual
   randomised salt which is used the derive the randomised key for the
   rest of the payload. 
   
   This means only the first 16 bytes will be in the same position each
   subsequent embed, while the rest of the payload will change. Keep in
   mind this is only for the absolute worst case, where the same
   password is being used to embed data on the same image. In any other
   situation where the password or image is changed then the payload
   distribution (including the initial random salt embed) would be
   drastically different
   
Finally, the "greyscale" mode is offered for situations where either all, or the majority of the image is in greyscale, and any pixel with it's R!=G!=B would stand out so we instead flip the bits of all channels. This roughly drops the capacity to a third but helps with concealment with certain images e.g. example image above.

## Usage

```
usage: dolos [-h] (-r | -w payload_filename.png) [-p password] [-g] image_filename

Embed and extract data in PNG images

positional arguments:
  image_filename

optional arguments:
  -h, --help            show this help message and exit
  -r, --read            Read image and write result to file
  -w payload_filename.png, --write payload_filename.png
                        Write payload to image
  -p password, --password password
                        Password to use while processing image
  -g, --greyscale       Treat all channels together (Less capacity, situational)

```
Embedding payload with password:

    python dolos.py image.png -w payload.txt -p password123

Extracting payload:

    python dolos.py image_payload_embedded.png -r -p password123

### Requirements
Can be installed the usual way with `pip install x`

    pycryptodome
    pillow
    numpy
