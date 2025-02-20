import { useState, useEffect } from 'react';

const NetworkMonitor = () => {
    const [networkData, setNetworkData] = useState({
        bytes_sent: 0,
        bytes_recv: 0,
        packets_sent: 0,
        packets_recv: 0,
        devices: []
    });
    const [isConnected, setIsConnected] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        const ws = new WebSocket('ws://localhost:8765');

        ws.onopen = () => {
            console.log('Connected to WebSocket server');
            setIsConnected(true);
            setError(null);
        };

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                setNetworkData(data);
            } catch (err) {
                console.error('Error parsing WebSocket message:', err);
                setError('Error receiving data');
            }
        };

        ws.onerror = (error) => {
            console.error('WebSocket error:', error);
            setError('Failed to connect to network monitor');
            setIsConnected(false);
        };

        ws.onclose = () => {
            console.log('Disconnected from WebSocket server');
            setIsConnected(false);
        };

        return () => {
            ws.close();
        };
    }, []);

    const formatBytes = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
    };

    if (error) {
        return <div className="text-red-500">{error}</div>;
    }

    return (
        <div className="p-4">
            <div className="mb-4">
                <h2 className="text-xl font-bold mb-2">Network Status</h2>
                <div className="grid grid-cols-2 gap-4">
                    <div className="bg-white p-4 rounded shadow">
                        <h3 className="font-semibold">Data Sent</h3>
                        <p>{formatBytes(networkData.bytes_sent)}</p>
                        <p>{networkData.packets_sent} packets</p>
                    </div>
                    <div className="bg-white p-4 rounded shadow">
                        <h3 className="font-semibold">Data Received</h3>
                        <p>{formatBytes(networkData.bytes_recv)}</p>
                        <p>{networkData.packets_recv} packets</p>
                    </div>
                </div>
            </div>

            <div>
                <h2 className="text-xl font-bold mb-2">Connected Devices</h2>
                <div className="grid gap-4">
                    {networkData.devices.map((device, index) => (
                        <div key={index} className="bg-white p-4 rounded shadow">
                            <h3 className="font-semibold">{device.hostname || 'Unknown Device'}</h3>
                            <p>IP: {device.ip}</p>
                            <p>MAC: {device.mac}</p>
                        </div>
                    ))}
                </div>
            </div>

            <div className="mt-4">
                <p className={`text-sm ${isConnected ? 'text-green-500' : 'text-red-500'}`}>
                    {isConnected ? 'Connected to network monitor' : 'Disconnected from network monitor'}
                </p>
            </div>
        </div>
    );
};

export default NetworkMonitor;
