from numpy.random import PCG64DXSM, Generator
from multiprocessing import Pool
from PIL import Image
import numpy as np
import argparse
import sys

#Encryption
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA384
from Crypto.Cipher import AES
import secrets

#Compression
import zlib

"""
When passed in an array of pixels will iterate through them and return an array of cordinates
for every pixel that's available to hide information. "plane" is passed so each thread can
know what plane it's processing to tag all cordinates with it i.e. r/g/b/a 0/1/2/3
"""
def process_plane(plane_pixels, width, height, plane, greyscale, channel_count):
    
    available_plane_pixels = [] 
    for i in range(width*height):
        x = i%width
        y = i//width
        
        #To account for edge effects set offsets
        if(x == 0):
            viewport_x_start = x
        else:
            viewport_x_start = x-1
            
        if(x == width - 1):
            viewport_x_end = x+1
        else:
            viewport_x_end = x+2

        if(y == 0):
            viewport_y_start = y
        else:
            viewport_y_start = y-1

        if(y == height - 1):
            viewport_y_end = y+1
        else:
            viewport_y_end = y+2
        
        current_pixel = plane_pixels[y][x]
        current_view = plane_pixels[viewport_y_start:viewport_y_end, viewport_x_start:viewport_x_end]

        #If greyscale mode then check each channel and only set pixel as available if all pass
        if(greyscale):
            #Check that there aren't any other pixels the same colour as the current one
            if((current_view == current_pixel).sum() == channel_count):
                #Now for each channel flip the bits and check if it's still valid:
                current_pixel_flipped = []
                for j in range(0, channel_count): #Do the same with the last bit of the current value flipped for each channel
                    current_pixel_channel = current_pixel[j]
                    if(current_pixel_channel % 2 == 0): #If even/odd flip the bit correctly
                        current_pixel_channel +=1
                    else:
                        current_pixel_channel -=1

                    current_pixel_flipped.append(current_pixel_channel)

                if((current_view == current_pixel_flipped).sum() == 0):
                    available_plane_pixels.append((x,y))

        else:   #Normal mode, slightly different flow but same logic
            #Check that there aren't any other pixels the same colour as the current one
            if((current_view == current_pixel).sum() == 1):

                #Do the same with the last bit of the current value flipped
                #If even/odd flip the bit correctly
                if(current_pixel % 2 == 0):
                    current_pixel +=1
                else:
                    current_pixel -=1

                #There should be no pixels with the same value as the flipped pixel
                if((current_view == current_pixel).sum() == 0):
                    available_plane_pixels.append((x,y, plane))

    return available_plane_pixels


"""
Helper function for embed() specifically to embed the input payload bytes into pil_pixels
according to the available_pixels array after shuffiling it with the key.
Note this will modify pil_pixels in place so we don't need to return it
"""
def embed_pixels(key, available_pixels, pil_pixels, payload, greyscale, channel_count):

    #Convert to bitstring
    payload_bitstring = ""
    for byte in payload:
        payload_bitstring += f'{byte:08b}'

    #Now we can start writing this to the image. First init RNG to shuffle the order of available pixels we'll write to.
    #Seed the RNG with the hash of the password (To prevent any vulnerabilities of the RNG from giving the AES key directly)
    h = SHA384.new()
    h.update(key)
    seed = int.from_bytes(h.digest(), byteorder="little")
    rng = Generator(PCG64DXSM(seed))
    rng.shuffle(available_pixels)

    #Write to these pixels
    for i, bit in enumerate(payload_bitstring):
        current_pixel = available_pixels[i]
        
        if(greyscale):
            x, y = current_pixel #Greyscale mode doesn't store channel as we'll write to all channels
        else:
            x, y, channel = current_pixel
            channel_count = 1   #If not in greyscale then we only write to 1 channel at a time, not all of them
            
        tmp_pixel = list(pil_pixels[x, y])  #We convert the tuple of the pixel to array to change it later for assignment back
    
        #The actual value of the pixel+appropriate channel we want to change
        #Flip the bit for each channel we're encoding in according to the payload
        for j in range(0, channel_count):

            if(greyscale):  #If in greyscale mode increment channel as range loop to write all
                channel = j
                
            target_pixel = tmp_pixel[channel]

            if(bit == "0"):
                if(target_pixel%2 == 1):    #If the last bit is currently 1 then subtract 1 to make it 0
                    tmp_pixel[channel] = target_pixel - 1
            elif(bit == "1"):
                if(target_pixel%2 == 0):    #If the last bit is currently 0 then add 1 to make it 1
                    tmp_pixel[channel] = target_pixel + 1

        #Write the altered pixel to the actual pixel
        pil_pixels[x, y] = tuple(tmp_pixel)


#Embed payload into image
def embed(payload_name, password, available_pixels, pil_pixels, img, greyscale, channel_count):
    #Prepare our payload. Compress, encrypt, convert to bitstring for easy handling for writing
    payload_file = open(payload_name, "rb")
    payload = payload_file.read()
    payload = payload_name.encode("utf-8") + b"\x00" + payload #Add the filename to the payload here and null terminate it
    payload = zlib.compress(payload, level = 9)
    payload_file.close()

    #Get the length as a 4 byte value which we'll save to the stream later
    payload_length = len(payload)
    payload_length_bytes = payload_length.to_bytes(4, byteorder="little")   #Max of 4gb payload, stores length of only payload itself

    #Check the payload isn't too large for the image (salt+gcm_tag + 4 byte length + compressed payload)
    total_payload_length = payload_length + 16 + 16 + 4
    available_pixel_bytes = (len(available_pixels)//8) - (16+16+4)
    
    if(total_payload_length > available_pixel_bytes):
        print(f"Payload too large for image.\nTrying to embed {total_payload_length} bytes while image can only hold {available_pixel_bytes}")
        sys.exit(1)
    else:
        print(f"Writing {total_payload_length} bytes to image with {available_pixel_bytes} byte capacity")

    #Encrypt it as 256 AES GCM
    #First we'll derive the key with PBKDF2, and eventually store the salt in the payload. The IV+key are both derived from the output of the kdf hence the SHA384 size
    salt = secrets.randbits(128).to_bytes(16, byteorder="little")
    kdf_result = PBKDF2(password, salt, 48, count=100000, hmac_hash_module=SHA384)  #Hash size must be >= requested bytes from IV
    key = kdf_result[0:32]
    IV = kdf_result[32:44]   #Note most implementations want a 12 byte IV for GCM so chop it out

    cipher = AES.new(key, AES.MODE_GCM, nonce=IV)
    encrypted_payload, GCM_tag = cipher.encrypt_and_digest(payload_length_bytes + payload)  #Encrypt payload_length (4 bytes) prefixed to payload

    #Before we write the payload we need to write its salt using a fixed known IV and derriving a "bootstrapping" key with it, so while extracting we can derrive the key again
    fixed_salt = bytes.fromhex("0252ccb6ec392867982b2095fdeefa23")
    kdf_result = PBKDF2(password, fixed_salt, 48, count=100000, hmac_hash_module=SHA384)  #Hash size must be >= requested bytes from IV
    bootstrap_key = kdf_result[0:32]    #Just to keep consistency as above we'll also only take the first 32 bytes+use same hash setup as above here, even though we won't use it for AES-256
    embed_pixels(bootstrap_key, available_pixels, pil_pixels, salt, greyscale, channel_count)   #Now using the fixed salt+derived key embed the inital random salt first
    
    #Now we've used up 16 bytes so delete the first 16*8 available pixels, and then write the actual payload using the random salt and key that was derived with it
    del available_pixels[0:(16*8)]
    embed_pixels(key, available_pixels, pil_pixels, (GCM_tag + encrypted_payload), greyscale, channel_count)   #We write the GCM tag first, then the encrypted payload

    #Now we've written the payload to the image and need to save it
    img.save("embedded_image.png")


"""
Helper function for extract. Returns read_length extracted bits (as bytearray) after
shuffiling the available_pixels according to the key
"""
def extract_pixels(key, available_pixels, pil_pixels, read_length, greyscale): #read_length is in bits
    #Now using this bootstrap key seed the RNG, and read out the first 16 bytes for the actual IV
    h = SHA384.new()
    h.update(key)
    seed = int.from_bytes(h.digest(), byteorder="little")
    rng = Generator(PCG64DXSM(seed))
    rng.shuffle(available_pixels)

    #Read first 16 bytes (128 bits) to bitstring
    recovered_data_bitstring = ""
    for i in range(0,read_length):
        current_pixel = available_pixels[i]

        if(greyscale):  #If greyscale then each pixel in the available_pixel is channel agnostic
            x, y = current_pixel
            current_payload_byte = pil_pixels[x, y][0]
        else:
            x, y, channel = current_pixel
            current_payload_byte = pil_pixels[x, y][channel]
            
        if(current_payload_byte % 2 == 1):
            recovered_data_bitstring += "1"
        else:
            recovered_data_bitstring += "0"

    #Convert bitstring to bytes for the proper salt
    recovered_data = int(recovered_data_bitstring, 2).to_bytes((len(recovered_data_bitstring) + 7) // 8, 'big')

    return recovered_data


#Extract payload from image using password
def extract(password, available_pixels, pil_pixels, greyscale):
    
    #First we derive the "bootstrap" key using the fixed IV and our input password
    fixed_salt = bytes.fromhex("0252ccb6ec392867982b2095fdeefa23")
    kdf_result = PBKDF2(password, fixed_salt, 48, count=100000, hmac_hash_module=SHA384)  #Hash size must be >= requested bytes from IV
    bootstrap_key = kdf_result[0:32]    #Just to keep consistency as above we'll also only take the first 32 bytes here and use the SHA384, even though we won't use it for AES-256

    #Now using this bootstrap key seed the RNG, and read out the first 16 bytes for the actual IV
    recovered_salt = extract_pixels(bootstrap_key, available_pixels, pil_pixels, 128, greyscale)

    #Now delete the pixels we've already read from
    del available_pixels[0:(16*8)]
    
    #And re-seed+shuffle after deriving the proper key with the salt above for the rest of the payload
    kdf_result = PBKDF2(password, recovered_salt, 48, count=100000, hmac_hash_module=SHA384)
    key = kdf_result[0:32]
    IV = kdf_result[32:44]   #Note most implementations want a 12 byte IV for GCM so chop it out

    #Now we can re-seed and shuffle the remaining available pixels to give us the final order to read from
    #Read off all the pixels at once, we'll parse/slice them later
    recovered_payload = extract_pixels(key, available_pixels, pil_pixels, (len(available_pixels)//8)*8, greyscale) #Make sure only to go to highest multiple of 8 to avoid conversion issues e.g. if we went to 12.4 bytes instead of 12

    #Get the GCM tag as the first 16 bytes
    GCM_tag = recovered_payload[0:16]
    payload_encrypted = recovered_payload[16:]

    #Partially decrypt the first 4 bytes to get the length of the rest, ignore GCM auth tag here, we'll check it later
    cipher = AES.new(key, AES.MODE_GCM, nonce=IV)
    payload_length_bytes = cipher.decrypt(payload_encrypted[0:4])
    payload_length = int.from_bytes(payload_length_bytes, byteorder="little")

    #Sanity check that the length isn't longer than the available pixels
    if(payload_length*8 > len(available_pixels)):
        print("Error, recovered payload length is larger than available bits in image, possibly corrupted/no payload")

    #Recover rest of payload and decrypt while checking tag
    cipher = AES.new(key, AES.MODE_GCM, nonce=IV)
    try:
        compressed_plaintext = cipher.decrypt_and_verify(payload_encrypted[0:payload_length+4], GCM_tag)   #+4 to account for prefixed length field, slice only up to the payload length
    except ValueError as error_value:
        if(error_value.args[0] == "MAC check failed"):
            print("Payload integrity violated, MAC check failed/no payload")
            sys.exit(1)
        else:
            raise Exception("Error during decryption")
        
    compressed_plaintext = compressed_plaintext[4:] #Drop first 4 bytes which were for the length
    plaintext = zlib.decompress(compressed_plaintext)

    #Get the filename from the plaintext, first N bytes null terminated
    null_term_index = plaintext.find(0)
    recovered_filename = plaintext[0:null_term_index].decode("utf-8")
    plaintext = plaintext[null_term_index+1:]

    print(f"""Payload recovered as "{recovered_filename}", writing to file...""")
    with open("recovered_" + recovered_filename, "wb") as fout:
        fout.write(plaintext)
        

#Main, return 0 on success. 1 in error, and 2 for syntax error
def main():
    
    #Setup argument parser
    parser = argparse.ArgumentParser(
                    prog='dolos',
                    description='Embed and extract data in PNG images')
 
    #Parser arguments
    parser.add_argument('image_filename', default = None)
    group  = parser.add_mutually_exclusive_group (required = True)
    
    group.add_argument("-r", "--read", default = None, action='store_true',
                        help = "Read image and write result to file")
     
    group.add_argument("-w", "--write", type = str, nargs = 1,
                        metavar = "payload_filename.png", default = None,
                        help = "Write payload to image")
    
    parser.add_argument("-p", "--password", type = str, nargs = 1,
                        metavar = "password", default = None,
                        help = "Password to use while processing image")

    parser.add_argument("-g", "--greyscale", default = None, action='store_true',
                        help = "Treat all channels together (Less capacity, situational)")

    #Parse arguments
    args = parser.parse_args()

    if args.image_filename != None:
        image_filename = args.image_filename
        
    if args.password != None:
        password = args.password[0]
    else:   #Default internal password
        password = "TheSpanishInquisition"

    greyscale = False
    if(args.greyscale != None):
        greyscale = True
        

    #Load the image, get relevant data
    img = Image.open(image_filename)
    
    width, height = img.size
    pil_pixels = img.load()
    pixels = np.asarray(img)

    #Split into individual channels
    if(img.mode == "RGB"):
        channel_count = 3
        r, g, b = pixels[:, :, 0], pixels[:, :, 1], pixels[:, :, 2]
        planes = [[r, width, height, 0, greyscale, channel_count], [g, width, height, 1, greyscale, channel_count], [b, width, height, 2, greyscale, channel_count]]   #Wrap each with h/w so each thread has access to them. Likewise with "r/g/b" as 0/1/2/3
    elif(img.mode == "RGBA"):
        channel_count = 4
        r, g, b, a = pixels[:, :, 0], pixels[:, :, 1], pixels[:, :, 2], pixels[:, :, 3]
        planes = [[r, width, height, 0, greyscale, channel_count], [g, width, height, 1, greyscale, channel_count], [b, width, height, 2, greyscale, channel_count], [a, width, height, 3, greyscale, channel_count]]
    else:
        print("Unsupported PNG format, only RGB/RGBA are supported") #Restricted to PNG RGB/RGBA to sidestep any odd formats/plaette issues
        
    #Will the available pixel cordinates for all channels together
    available_pixels = []
    print("Checking for eligible pixels in image...")

    if(greyscale):
        available_pixels = process_plane(pixels, width, height, None, greyscale, channel_count)
    else:
        #Make one thread per channel
        with Pool(channel_count) as p:
            if(not greyscale):
                thread_returns = p.starmap(process_plane, planes)
            else:
                thread_returns = p.starmap(process_plane, pixels)

        for result in thread_returns:
            available_pixels.extend(result)

        
    print("Writing/reading image...")
    if args.read != None:
        extract(password, available_pixels, pil_pixels, greyscale)
        
    if args.write != None:
        payload_name = args.write[0]
        embed(payload_name, password, available_pixels, pil_pixels, img, greyscale, channel_count)
        
    print("Finished.")
    
    return 0    #Success

#Only run main if parent process, not import/thread
if __name__ == '__main__':
    sys.exit(main())
