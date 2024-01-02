# -*- coding: utf-8 -*-
"""
Created on Mon Jan  1 21:01:43 2024

@author: yusuf
"""

import requests

def virustotal_sorgula(api_key, hash_degeri):
    """
    Virustotal API'sini kullanarak dosyanın güvenlik durumunu sorgular.
    """
    url = f"https://www.virustotal.com/api/v3/files/{hash_degeri}"
    headers = {
        "x-apikey": api_key,
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        result = response.json()

        # if your question value true show the this message 
        if "data" in result and "attributes" in result["data"]:
            attributes = result["data"]["attributes"]
            print(f"İlgili Dosyanın Virustotal Sonuçları:\n{attributes}")
        else:
            print("Virustotal'da sonuç bulunamadı.")

    except requests.exceptions.RequestException as e:
        print(f"Hata: {e}")

# enter the your API key 
api_key = "BURAYA_API_ANAHTARINIZI_YAZIN"
# enter the Hash code your sample file  (for example enter hash code of yusuf.pdf file)
hash_degeri = "BURAYA_HASH_DEGERINIZI_YAZIN"

# call the function 
virustotal_sorgula(api_key, hash_degeri)