# Item Catalog
Made by Lyn Scott with Python 2.7, Vagrant 1.9.7 and VirtualBox 5.1.26.

## Intro
This code is designed to connect to the PostgreSQL database of items and respective catalogs 
for a fictional website. The website features google and facebook sign-in options as well as user protected content. 

##### Requirements:

  - [Install VirtualBox](https://www.virtualbox.org/wiki/Downloads)
  - [Install Vagrant](https://www.vagrantup.com/downloads.html)
  - [Clone/Download the Item-Catalog repo](https://github.com/lynscott/Item-Catalog)
  - Download the VM Configuration: [here](https://github.com/lynscott/Log-Analysis/blob/master/news/VagrantFile)
  
##### Setup:
  - Unzip Item-Catalog repo, place the _catalog_ folder in the same dir as the _VagrantFile_ file. 
  - In your terminal, change into your vagrant directory, run `vagrant up` to start your VM.
  - Enter `vagrant ssh` to enter your VM's terminal. `cd` into the catalog directory of shared folder.
  - Run the file with: `python catalog.py`.
    - _Note: use only with python 2.7. 
 
