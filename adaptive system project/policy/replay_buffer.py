from collections import deque
import random
 
class ReplayBuffer:
    def __init__(self, maxlen=5000, batch_size=32, train_every=50):
        self.buffer      = deque(maxlen=maxlen)  
        self.batch_size  = batch_size
        self.train_every = train_every          
        self._step_count = 0
 
    def push(self, state_idx, action, reward, next_state_idx):
        self.buffer.append((state_idx, action, reward, next_state_idx))
        self._step_count += 1
 
    def should_train(self) -> bool:
        return (
            self._step_count % self.train_every == 0
            and len(self.buffer) >= self.batch_size
        )
 
    def sample(self) -> list:
        return random.sample(list(self.buffer), self.batch_size)
 
    def __len__(self): return len(self.buffer)
 
