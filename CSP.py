"""
SCP Quality Automation System
Author: REDAOUZIDANE
Version: 1.0
Description: Secure file transfer with Six Sigma quality monitoring
"""

import paramiko
from scp import SCPClient
import hashlib
import numpy as np
from scipy import stats
import time
import logging
from dataclasses import dataclass
from typing import List, Dict, Optional
import matplotlib.pyplot as plt
import json
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scp_quality.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class TransferMetrics:
    filename: str
    size_bytes: int
    duration_sec: float
    throughput_mbps: float
    sha256_checksum: str
    timestamp: str

class SCPSigmaTransfer:
    """Advanced SCP client with Six Sigma quality monitoring"""
    
    def __init__(self, host: str, username: str, key_path: str, 
                 bandwidth_limit: Optional[int] = None):
        """
        Initialize secure transfer client
        
        Args:
            host: Remote server hostname/IP
            username: SSH username
            key_path: Path to private key
            bandwidth_limit: Optional bandwidth limit in KB/s
        """
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.ssh.connect(host, username=username, key_filename=key_path)
        self.scp = SCPClient(
            self.ssh.get_transport(), 
            socket_timeout=15,
            bwlimit=bandwidth_limit
        )
        self.metrics: List[TransferMetrics] = []
        
    def secure_transfer(
        self,
        local_path: str,
        remote_path: str,
        verify: bool = True,
        retries: int = 3
    ) -> bool:
        """
        Perform secure file transfer with quality checks
        
        Args:
            local_path: Local file path
            remote_path: Remote destination path
            verify: Enable checksum verification
            retries: Number of retry attempts
            
        Returns:
            bool: True if transfer succeeded with verification
        """
        for attempt in range(1, retries + 1):
            try:
                start_time = time.time()
                
                # Calculate local checksum before transfer
                local_hash = self._calculate_sha256(local_path)
                
                # Perform secure transfer
                self.scp.put(local_path, remote_path)
                transfer_time = time.time() - start_time
                
                # Verify remote checksum
                if verify:
                    remote_hash = self._get_remote_sha256(remote_path)
                    if local_hash != remote_hash:
                        raise IntegrityError("Checksum mismatch")
                
                # Record metrics
                file_size = Path(local_path).stat().st_size
                metrics = TransferMetrics(
                    filename=local_path,
                    size_bytes=file_size,
                    duration_sec=transfer_time,
                    throughput_mbps=(file_size * 8) / (transfer_time * 1_000_000),
                    sha256_checksum=local_hash,
                    timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
                )
                self.metrics.append(metrics)
                
                logger.info(f"Transfer successful: {local_path} -> {remote_path}")
                return True
                
            except Exception as e:
                logger.error(f"Attempt {attempt}/{retries} failed: {str(e)}")
                if attempt == retries:
                    logger.critical("Max retries exceeded")
                    return False
                time.sleep(2 ** attempt)  # Exponential backoff

    def _calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA-256 hash of local file"""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _get_remote_sha256(self, remote_path: str) -> str:
        """Get SHA-256 hash of remote file"""
        stdin, stdout, stderr = self.ssh.exec_command(f"sha256sum {remote_path}")
        return stdout.read().split()[0].decode()
    
    def generate_quality_report(self) -> Dict:
        """Generate Six Sigma quality report"""
        throughputs = [m.throughput_mbps for m in self.metrics]
        
        if not throughputs:
            return {}
            
        analyzer = SixSigmaAnalyzer(throughputs)
        report = {
            "throughput_stats": {
                "mean": np.mean(throughputs),
                "std_dev": np.std(throughputs),
                "cpk": analyzer.calculate_cpk(100, 10),  # Example limits
                "sigma_level": analyzer.calculate_sigma_level()
            },
            "transfer_metrics": [vars(m) for m in self.metrics]
        }
        return report
    
    def plot_control_chart(self, save_path: Optional[str] = None):
        """Generate control chart visualization"""
        throughputs = [m.throughput_mbps for m in self.metrics]
        if not throughputs:
            return
            
        analyzer = SixSigmaAnalyzer(throughputs)
        limits = analyzer.control_chart()
        
        plt.figure(figsize=(12, 6))
        plt.plot(throughputs, 'b-', label='Throughput (Mbps)')
        plt.axhline(limits['upper_control_limit'], color='r', linestyle='--', label='UCL')
        plt.axhline(limits['lower_control_limit'], color='r', linestyle='--', label='LCL')
        plt.axhline(np.mean(throughputs), color='g', label='Mean')
        
        plt.title('SCP Transfer Throughput Control Chart')
        plt.xlabel('Transfer #')
        plt.ylabel('Throughput (Mbps)')
        plt.legend()
        plt.grid(True)
        
        if save_path:
            plt.savefig(save_path)
        else:
            plt.show()
    
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.scp.close()
        self.ssh.close()

class SixSigmaAnalyzer:
    """Six Sigma statistical analysis tools"""
    
    def __init__(self, data: List[float]):
        self.data = np.array(data)
        
    def calculate_cpk(self, usl: float, lsl: float) -> float:
        """Calculate process capability index (Cpk)"""
        if len(self.data) < 2:
            return 0.0
            
        std = np.std(self.data)
        mean = np.mean(self.data)
        return min((usl-mean)/(3*std), (mean-lsl)/(3*std))
        
    def control_chart(self) -> Dict[str, float]:
        """Generate control chart limits"""
        if len(self.data) < 2:
            return {}
            
        std = np.std(self.data)
        mean = np.mean(self.data)
        return {
            'upper_control_limit': mean + 3*std,
            'lower_control_limit': mean - 3*std,
            'mean': mean
        }
    
    def calculate_sigma_level(self) -> float:
        """Calculate Sigma level from defect rate"""
        if len(self.data) < 2:
            return 0.0
            
        # Example: Consider throughput < 10 Mbps as defect
        defects = sum(1 for x in self.data if x < 10)
        defect_rate = defects / len(self.data)
        
        if defect_rate >= 1:
            return 0.0
            
        return stats.norm.ppf(1 - defect_rate) + 1.5  # 1.5 sigma shift

class IntegrityError(Exception):
    """Custom exception for data integrity failures"""
    pass

# Example Usage
if __name__ == "__main__":
    config = {
        "host": "example.com",
        "username": "user",
        "key_path": "/path/to/private_key",
        "bandwidth_limit": 50000  # 50 MB/s
    }
    
    files_to_transfer = [
        ("/local/path/file1.txt", "/remote/path/file1.txt"),
        ("/local/path/file2.dat", "/remote/path/file2.dat")
    ]
    
    with SCPSigmaTransfer(**config) as client:
        for local, remote in files_to_transfer:
            client.secure_transfer(local, remote)
        
        # Generate reports
        report = client.generate_quality_report()
        with open("quality_report.json", "w") as f:
            json.dump(report, f, indent=2)
            
        client.plot_control_chart("throughput_chart.png")