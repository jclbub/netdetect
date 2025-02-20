import { create } from 'zustand';

export const useDeviceStore = create((set) => ({
  devices: [],
  loading: true,
  error: null,
  scanStatus: 'idle',
  wsRef: { current: null },

  setDevices: (devices) => set({ devices }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
  setScanStatus: (scanStatus) => set({ scanStatus }),
}));
