from locust import HttpUser, task, between, events
import random, csv, time, os
 
TEST_SENTENCES = [
    'This product is absolutely incredible and changed my life.',
    'Terrible customer service. I will never buy from them again.',
    'Decent quality for the price, nothing exceptional.',
    'The software crashes constantly and support is non-existent.',
    'Best purchase I have made this year. Highly recommended.',
    'Average performance, meets expectations but no more.',
    'Absolutely love this product! Works perfectly every time.',
    'Complete waste of money. Broke after two days of use.',
]
 

RESULTS_FILE = 'benchmark/results1/locust_results.csv'
os.makedirs('benchmark/results1', exist_ok=True)
 
class SentimentUser(HttpUser):
    def on_start(self):
        self.client.verify = False

    wait_time = between(0.5, 2.0)
    
    def on_start(self):
        
        self.client.verify = False
    @task(5)  
    def predict_medium(self):
        """Standard request — medium sensitivity."""
        self.client.post(
            '/predict',
            json={'text': random.choice(TEST_SENTENCES), 'sensitivity': 'medium'},
            name='/predict [medium]'
        )
 
    @task(2)
    def predict_high(self):
        """High sensitivity — policy engine must use post_quantum."""
        self.client.post(
            '/predict',
            json={'text': random.choice(TEST_SENTENCES), 'sensitivity': 'high'},
            name='/predict [high]'
        )
 
    @task(1)
    def predict_low(self):
        """Low sensitivity — policy engine may use classical."""
        self.client.post(
            '/predict',
            json={'text': random.choice(TEST_SENTENCES), 'sensitivity': 'low'},
            name='/predict [low]'
        )

    @task(1)
    def health_check(self):
        self.client.get('/health')
 
    @task(1)
    def get_metrics(self):
        self.client.get('/metrics')
 
class HeavyLoadUser(HttpUser):
    def on_start(self):
        self.client.verify = False

    wait_time = between(0.1, 0.5)
 
    @task
    def stress_predict(self):
        self.client.post(
            '/predict',
            json={'text': 'Quick stress test request', 'sensitivity': 'low'},
            name='/predict [stress]'
        )
