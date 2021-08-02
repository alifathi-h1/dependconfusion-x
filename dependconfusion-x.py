from concurrent.futures import ThreadPoolExecutor, as_completed
import requests,sys, argparse, os,pyfiglet
from colorama import Fore, Style
from slack_webhook import Slack
from threading import Lock


class DependencyConfusion:

	def __init__(self, urls_file, threads, slack_option):
		self.dependencies_names = ['dependencies', 'devDependencies','peerDependencies']
		self.threads = threads
		self.slack_option = slack_option
		self.lock = Lock()
		if self.slack_option:
			try:
				self.slack=Slack(url=os.environ.get("slack_webhook"))
			except Exception as E:
				print(E)
				print(Fore.RED+'\n[--] Please Configure slack_webhook as Env Variable first. \n')
				sys.exit()				

	def notify(self,msg):

		try:		
			self.slack.post(text=msg)
		except Exception as E:
			print(Fore.RED+'\n[--] There was error while sending via Slack: ' + str(E) + ' Skipping...')

	def print_result(self,color, msg):
		print(color+msg)


	def verify(self, host):
		try:
			host = host.strip()
			if host.endswith("/package.json") != True:
				host = str(host)+"/package.json"


			if host.startswith("https://") != True and host.startswith("http://") != True :
					host = "http://"+str(host)

			response = requests.get(host)
			
			if response.status_code == 200:
				valid_depen = 0
				vulnerable_depen = []
				for name in self.dependencies_names: 
					try:
						depen = response.json()[name]
						for package in depen:
							check = requests.get("https://registry.npmjs.org/-/v1/search?text="+package)
							results = check.json()['objects']
							if len(results) > 0:
								valid_depen += 1  
							else:
								vulnerable_depen.append(package)
								if self.slack_option:
									self.notify(msg="\n[--] "+str(package)+" package on "+ str(host) + " seems to be vulnerable!")
					except:    
						pass 

				self.lock.acquire()
				if len(vulnerable_depen) > 0:
					self.print_result(Fore.GREEN, "\n[**] " + str(host) + ":\n[++] Valid Dependencies: "+ str(valid_depen) + Fore.RED+"\n[--] Vulnerable dependencies:"+ str(vulnerable_depen)+"\n")
				else:
					self.print_result(Fore.GREEN, "\n[**] " + str(host) + ":\n[++] Valid Dependencies: "+ str(valid_depen)+"\n")					
				self.lock.release()

		except requests.exceptions.ConnectionError:

			self.print_result(Fore.White,"\n[xx] Connection refused for "+ host)

	def main(self):
		hosts = []
		for host in urls_file.readlines():
			hosts.append(host)

		total_hosts = str(len(hosts))
		msg = "\n[++] We started scanning " + total_hosts + " targets for Dependency Confusion ...\n"
		self.print_result(Fore.GREEN,msg)
		print('-'*70)
		if self.slack_option:	
			self.notify(msg=msg)
		
		processes = []
		with ThreadPoolExecutor(max_workers=self.threads) as executor:
			for host in hosts:
				processes.append(executor.submit(self.verify, host))

		msg = "\n[++] We finished scanning " + total_hosts + " targets for Dependency Confusion ...\n"
		print('-'*70)
		self.print_result(Fore.GREEN,msg)
		if self.slack_option:
			self.notify(msg=msg)



banner = pyfiglet.figlet_format("DependaCon - X  T o o l", width=130,  justify='center')
print(Fore.GREEN+'\n \n'+banner)
print('Developed By @Alifathi-h1 \n\n '.center(90))


parser = argparse.ArgumentParser(description='DependConfusion-X Tool is written in Python3 that scans and monitors list of hosts for Dependency Confusion.\n\n')
parser.add_argument('-l', '--urls', help='File containing list of domains to scan',required=True, type=argparse.FileType('r'))
parser.add_argument("-t", "--threads", help="Number of Threads, default is 10", type=int, default=10)
parser.add_argument("-s", "--slack", help="Notify using Slack Webhook URL", default=False, action=argparse.BooleanOptionalAction)
args = parser.parse_args()

urls_file= args.urls
threads = args.threads
slack_option = args.slack

dependency_confusion = DependencyConfusion(urls_file,threads, slack_option)
dependency_confusion.main()
