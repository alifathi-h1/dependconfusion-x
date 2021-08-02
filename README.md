 <p align="center">
  <img width="150" src="https://user-images.githubusercontent.com/55149010/127813196-70d674aa-6630-4c9b-a21d-a548237c51e5.png">
<h1 align="center">DependConfusion-X</h1>
</p>


DependConfusion-X Tool is written in Python3, and allows security researcher/bug bounty hunter to scan and monitor list of hosts for Dependency Confusion. Currently, it extracts application dependencies from ```https://example.com/package.json```, and tries to find them on https://registry.npmjs.org. 


<img width="1308" alt="image" src="https://user-images.githubusercontent.com/55149010/127814435-a86b4123-41a9-4d8d-8718-34cf6e36caa2.png">


## Requirements <br>
* Python 3
* Linux/Windows/MAC OSX
* Slack Webhook (Optional)

## Installation 

* Installing Python dependencies 

   ```pip3 install -r requirements.txt```

* Configuring Slack Webhook as env variable

   ```export  slack_webhook=""```
 

## Usage

* To enable Dependabot for Org repos: 

   ```python3 dependconfusion-x.py -l hosts_file [-slack, --threads 20] ```
   


