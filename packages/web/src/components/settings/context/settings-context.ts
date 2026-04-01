import type { SettingsContextValue } from '../types';

import { createContext } from 'react';

// ----------------------------------------------------------------------

export const SettingsContext = createContext<SettingsContextValue | undefined>(undefined);
