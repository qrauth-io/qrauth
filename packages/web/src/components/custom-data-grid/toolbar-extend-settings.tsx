import type { DataGridProps } from '@mui/x-data-grid';
import type { ToolbarButtonBaseProps } from './toolbar-core';

import { useState, useCallback } from 'react';
import { usePopover } from 'minimal-shared/hooks';

import Menu from '@mui/material/Menu';
import Tooltip from '@mui/material/Tooltip';
import Divider from '@mui/material/Divider';
import MenuItem from '@mui/material/MenuItem';
import { svgIconClasses } from '@mui/material/SvgIcon';

import {
  EyeIcon,
  EyeCloseIcon,
  DensityCompactIcon,
  DensityStandardIcon,
  DensityComfortableIcon,
} from 'src/theme/core/components/mui-x-data-grid';

import { Iconify } from '../iconify';
import { ToolbarButtonBase } from './toolbar-core';

// ----------------------------------------------------------------------

/**
 * Docs
 * https://mui.com/x/react-data-grid/components/toolbar/
 */

export type GridSettingsState = Pick<
  DataGridProps,
  'density' | 'showCellVerticalBorder' | 'showColumnVerticalBorder'
>;

export type CustomToolbarSettingsButtonProps = {
  settings: GridSettingsState;
  onChangeSettings: React.Dispatch<React.SetStateAction<GridSettingsState>>;
};

export function useToolbarSettings(
  initialSettings?: Partial<GridSettingsState>
): CustomToolbarSettingsButtonProps {
  const defaultSettings: GridSettingsState = {
    density: 'standard',
    showCellVerticalBorder: false,
    showColumnVerticalBorder: false,
    ...initialSettings,
  };

  const [settings, setSettings] = useState<GridSettingsState>(defaultSettings);

  return {
    settings,
    onChangeSettings: setSettings,
  };
}

// ----------------------------------------------------------------------

const GRID_DENSITY_OPTIONS: {
  label: string;
  value: GridSettingsState['density'];
  icon: React.ReactNode;
}[] = [
  { label: 'Compact density', value: 'compact', icon: <DensityCompactIcon /> },
  { label: 'Standard density', value: 'standard', icon: <DensityStandardIcon /> },
  {
    label: 'Comfortable density',
    value: 'comfortable',
    icon: <DensityComfortableIcon />,
  },
];

export function CustomToolbarSettingsButton({
  settings,
  onChangeSettings,
  showLabel,
  label = 'Settings',
}: Pick<ToolbarButtonBaseProps, 'label' | 'showLabel'> & CustomToolbarSettingsButtonProps) {
  const { open, anchorEl, onClose, onOpen } = usePopover();

  const handleChangeDensity = useCallback(
    (value: GridSettingsState['density']) => {
      onChangeSettings((prev) => ({ ...prev, density: value }));
    },
    [onChangeSettings]
  );

  const handleToggleSetting = useCallback(
    (key: 'showCellVerticalBorder' | 'showColumnVerticalBorder') => {
      onChangeSettings((prev) => ({ ...prev, [key]: !prev[key] }));
    },
    [onChangeSettings]
  );

  const renderToggleOption = (
    menuItemLabel: string,
    key: 'showColumnVerticalBorder' | 'showCellVerticalBorder'
  ) => {
    const selected = settings[key];

    return (
      <MenuItem key={key} selected={selected} onClick={() => handleToggleSetting(key)}>
        {selected ? <EyeIcon /> : <EyeCloseIcon />}
        {menuItemLabel}
      </MenuItem>
    );
  };

  return (
    <>
      <Tooltip title={label}>
        <ToolbarButtonBase
          id="settings-menu-trigger"
          aria-controls="settings-menu"
          aria-haspopup="true"
          aria-expanded={open ? 'true' : undefined}
          onClick={onOpen}
          label={label}
          icon={<Iconify icon="solar:settings-bold" />}
          showLabel={showLabel}
        />
      </Tooltip>

      <Menu
        id="settings-menu"
        open={open}
        anchorEl={anchorEl}
        onClose={onClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
        slotProps={{
          list: {
            'aria-labelledby': 'settings-menu-trigger',
            sx: {
              [`& .${svgIconClasses.root}`]: {
                mr: 2,
                fontSize: 20,
              },
            },
          },
        }}
      >
        {GRID_DENSITY_OPTIONS.map((option) => (
          <MenuItem
            key={option.value}
            selected={settings.density === option.value}
            onClick={() => handleChangeDensity(option.value)}
          >
            {option.icon}
            {option.label}
          </MenuItem>
        ))}

        <Divider />

        {renderToggleOption('Show column borders', 'showColumnVerticalBorder')}
        {renderToggleOption('Show cell borders', 'showCellVerticalBorder')}
      </Menu>
    </>
  );
}
