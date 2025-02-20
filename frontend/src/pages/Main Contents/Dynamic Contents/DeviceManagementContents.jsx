import React, { useEffect } from 'react';
import { useNotifications } from "../../../context/NotificationsContext";
import { useDeviceContext } from '../../../context/DeviceContext';

const DeviceManagementContents = () => {
  const { addNotification } = useNotifications();
  const { 
    devices, 
    loading, 
    error, 
    scanStatus,
    wsRef,
    setDevices,
    setLoading,
    setError,
    setScanStatus,
  } = useDeviceContext();

  useEffect(() => {
    // Only create a new WebSocket if one doesn't exist
    if (!wsRef.current) {
      const ws = new WebSocket('ws://localhost:8000/ws/network-scanner/');
      wsRef.current = ws;
      
      ws.onopen = () => {
        console.log('WebSocket Connected');
        setLoading(false);
        setError(null);
        
        // Start scanning when connected
        ws.send(JSON.stringify({ command: 'start_scan' }));
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          console.log('Received WebSocket data:', data);
          
          // Handle different message types
          switch (data.type) {
            case 'status':
              setScanStatus(data.status);
              setLoading(data.status === 'scanning');
              setError(null);
              break;
              
            case 'devices':
              // Update devices and notify about new ones
              const oldDevices = new Set(devices.map(d => d.mac_address));
              const newDevices = data.devices.filter(d => !oldDevices.has(d.mac_address));
              
              // Notify about new devices
              newDevices.forEach(device => {
                addNotification({
                  title: 'New Device Detected',
                  message: `${device.hostname || 'Unknown Device'} (${device.ip_address})`,
                  type: 'info'
                });
              });
              
              setDevices(data.devices);
              setLoading(false);
              setError(null);
              break;
              
            case 'error':
              setError(data.error);
              setLoading(false);
              addNotification({
                title: 'Scanning Error',
                message: data.error,
                type: 'error'
              });
              break;
              
            default:
              console.warn('Unknown message type:', data);
          }
        } catch (error) {
          console.error('Error processing WebSocket message:', error);
        }
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        setError('Connection error - Make sure the backend server is running');
        setLoading(false);
        addNotification({
          title: 'Connection Error',
          message: 'Failed to connect to device scanner. Is the backend running?',
          type: 'error'
        });
      };

      ws.onclose = () => {
        console.log('WebSocket Disconnected');
        setError('Connection closed - Attempting to reconnect...');
        setLoading(false);
        
        // Try to reconnect after 5 seconds
        setTimeout(() => {
          if (wsRef.current === ws) { // Only reconnect if this is still the current connection
            wsRef.current = null; // Clear the ref so we can reconnect
          }
        }, 5000);
      };

      // Cleanup on unmount
      return () => {
        // Don't actually close the WebSocket when unmounting
        // This allows it to stay connected when navigating away
      };
    }
  }, []); // Empty dependency array - only run once on mount

  return (
    <div className="p-4">
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-2xl font-bold text-white">Connected Devices</h2>
        <div className="flex items-center gap-2">
          {loading && (
            <div className="flex items-center text-blue-400">
              <svg className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              Scanning...
            </div>
          )}
          {scanStatus === 'stopped' && (
            <span className="text-gray-400">Scan stopped</span>
          )}
        </div>
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-500 text-red-200 p-3 rounded mb-4">
          {error}
        </div>
      )}

      <div className="bg-gray-900 rounded-lg shadow overflow-hidden">
        <table className="min-w-full divide-y divide-gray-700">
          <thead className="bg-gray-800">
            <tr>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">Hostname</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">IP Address</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">MAC Address</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">Vendor</th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-300">Last Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700">
            {devices.length === 0 ? (
              <tr>
                <td colSpan="5" className="px-4 py-8 text-center text-gray-400">
                  {loading ? (
                    'Scanning for devices...'
                  ) : (
                    'No devices found'
                  )}
                </td>
              </tr>
            ) : (
              devices.map((device, index) => (
                <tr key={device.mac_address || index} className="hover:bg-gray-800/50">
                  <td className="px-4 py-3 text-sm text-gray-300">{device.hostname || 'Unknown'}</td>
                  <td className="px-4 py-3 text-sm text-gray-300">{device.ip_address}</td>
                  <td className="px-4 py-3 text-sm text-gray-300">{device.mac_address}</td>
                  <td className="px-4 py-3 text-sm text-gray-300">{device.vendor || 'Unknown'}</td>
                  <td className="px-4 py-3 text-sm text-gray-300">
                    {new Date(device.last_seen * 1000).toLocaleString()}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default DeviceManagementContents;
