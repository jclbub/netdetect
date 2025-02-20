import React, { createContext, useContext, useState, useRef } from 'react';

const DeviceContext = createContext(null);

export const DeviceProvider = ({ children }) => {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [scanStatus, setScanStatus] = useState('idle');
  const wsRef = useRef(null);

  const value = {
    devices,
    loading,
    error,
    scanStatus,
    wsRef,
    setDevices,
    setLoading,
    setError,
    setScanStatus,
  };

  return (
    <DeviceContext.Provider value={value}>
      {children}
    </DeviceContext.Provider>
  );
};

export const useDeviceContext = () => {
  const context = useContext(DeviceContext);
  if (!context) {
    throw new Error('useDeviceContext must be used within a DeviceProvider');
  }
  return context;
};
