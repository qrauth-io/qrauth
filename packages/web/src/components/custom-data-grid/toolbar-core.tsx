import type { ButtonProps } from '@mui/material/Button';
import type { QuickFilterProps } from '@mui/x-data-grid';
import type { Theme, SxProps } from '@mui/material/styles';
import type { TextFieldProps } from '@mui/material/TextField';
import type { IconButtonProps } from '@mui/material/IconButton';

import { usePopover } from 'minimal-shared/hooks';

import Box from '@mui/material/Box';
import Menu from '@mui/material/Menu';
import Badge from '@mui/material/Badge';
import Button from '@mui/material/Button';
import Tooltip from '@mui/material/Tooltip';
import MenuItem from '@mui/material/MenuItem';
import { styled } from '@mui/material/styles';
import TextField from '@mui/material/TextField';
import IconButton from '@mui/material/IconButton';
import InputAdornment from '@mui/material/InputAdornment';
import {
  ExportCsv,
  ExportPrint,
  QuickFilter,
  QuickFilterClear,
  useGridApiContext,
  FilterPanelTrigger,
  QuickFilterControl,
  ColumnsPanelTrigger,
} from '@mui/x-data-grid';

import { ExportIcon, FilterIcon, ViewColumnsIcon } from 'src/theme/core/components/mui-x-data-grid';

import { Iconify } from '../iconify';

// ----------------------------------------------------------------------

type BaseProps = Partial<ButtonProps & IconButtonProps>;

export type ToolbarButtonBaseProps = BaseProps & {
  label?: string;
  showLabel?: boolean;
  icon: React.ReactNode;
};

export function ToolbarButtonBase({
  sx,
  label,
  icon,
  showLabel = true,
  ...other
}: ToolbarButtonBaseProps) {
  const Component: React.ElementType = showLabel ? Button : IconButton;

  const baseProps: BaseProps = showLabel ? { size: 'small' } : {};

  return (
    <Tooltip title={label}>
      <Component
        {...baseProps}
        {...other}
        sx={[
          {
            gap: showLabel ? 0.75 : 0,
            '& svg': {
              width: showLabel ? 18 : 20,
              height: showLabel ? 18 : 20,
            },
          },
          ...(Array.isArray(sx) ? sx : [sx]),
        ]}
      >
        {icon}
        {showLabel && label}
      </Component>
    </Tooltip>
  );
}

// ----------------------------------------------------------------------

export function CustomToolbarColumnsButton({
  showLabel,
}: Pick<ToolbarButtonBaseProps, 'showLabel'>) {
  const apiRef = useGridApiContext();
  const label = apiRef.current.getLocaleText('toolbarColumns');

  return (
    <ColumnsPanelTrigger
      render={(props) => (
        <ToolbarButtonBase
          {...props}
          label={String(label)}
          icon={<ViewColumnsIcon />}
          showLabel={showLabel}
        />
      )}
    />
  );
}

// ----------------------------------------------------------------------

export function CustomToolbarFilterButton({
  showLabel,
}: Pick<ToolbarButtonBaseProps, 'showLabel'>) {
  const apiRef = useGridApiContext();
  const label = apiRef.current.getLocaleText('toolbarFilters');

  return (
    <FilterPanelTrigger
      render={(props, state) => (
        <ToolbarButtonBase
          {...props}
          label={String(label)}
          showLabel={showLabel}
          icon={
            <Badge variant="dot" color="error" badgeContent={state.filterCount}>
              <FilterIcon />
            </Badge>
          }
        />
      )}
    />
  );
}

// ----------------------------------------------------------------------

export function CustomToolbarExportButton({
  showLabel,
}: Pick<ToolbarButtonBaseProps, 'showLabel'>) {
  const apiRef = useGridApiContext();
  const label = apiRef.current.getLocaleText('toolbarExport');
  const csvLabel = apiRef.current.getLocaleText('toolbarExportCSV');
  const printLabel = apiRef.current.getLocaleText('toolbarExportPrint');

  const { open, anchorEl, onClose, onOpen } = usePopover();

  return (
    <>
      <ToolbarButtonBase
        id="export-menu-trigger"
        aria-controls="export-menu"
        aria-haspopup="true"
        aria-expanded={open ? 'true' : undefined}
        onClick={onOpen}
        label={String(label)}
        icon={<ExportIcon />}
        showLabel={showLabel}
      />

      <Menu
        id="export-menu"
        open={open}
        anchorEl={anchorEl}
        onClose={onClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
        transformOrigin={{ vertical: 'top', horizontal: 'right' }}
        slotProps={{
          list: {
            'aria-labelledby': 'export-menu-trigger',
          },
        }}
      >
        <ExportPrint render={<MenuItem />} onClick={onClose}>
          {printLabel}
        </ExportPrint>

        <ExportCsv render={<MenuItem />} onClick={onClose}>
          {csvLabel}
        </ExportCsv>
      </Menu>
    </>
  );
}

// ----------------------------------------------------------------------

export type CustomToolbarQuickFilterProps = QuickFilterProps & {
  sx?: SxProps<Theme>;
  slotProps?: {
    textField?: TextFieldProps;
  };
};

export function CustomToolbarQuickFilter({
  sx,
  slotProps,
  ...other
}: CustomToolbarQuickFilterProps) {
  const apiRef = useGridApiContext();
  const label = apiRef.current.getLocaleText('toolbarQuickFilterLabel');
  const placeholder = apiRef.current.getLocaleText('toolbarQuickFilterPlaceholder');

  return (
    <QuickFilter
      {...other}
      render={(props) => (
        <Box
          {...props}
          sx={[{ width: 1, maxWidth: { md: 260 } }, ...(Array.isArray(sx) ? sx : [sx])]}
        >
          <QuickFilterControl
            render={({ ref, ...controlProps }, state) => (
              <TextField
                {...controlProps}
                fullWidth
                inputRef={ref}
                aria-label={label}
                placeholder={placeholder}
                slotProps={{
                  input: {
                    startAdornment: (
                      <InputAdornment position="start">
                        <Iconify icon="eva:search-fill" />
                      </InputAdornment>
                    ),
                    endAdornment: state.value ? (
                      <InputAdornment position="end">
                        <QuickFilterClear edge="end" size="small" aria-label="Clear search">
                          <Iconify icon="mingcute:close-line" width={16} />
                        </QuickFilterClear>
                      </InputAdornment>
                    ) : null,
                    ...controlProps.slotProps?.input,
                  },
                  ...controlProps.slotProps,
                  ...slotProps?.textField?.slotProps,
                }}
                {...slotProps?.textField}
              />
            )}
          />
        </Box>
      )}
    />
  );
}

// ----------------------------------------------------------------------

export const ToolbarContainer = styled('div')(({ theme }) => ({
  width: '100%',
  display: 'flex',
  flexWrap: 'wrap',
  flexDirection: 'column',
  gap: theme.spacing(2),
  [theme.breakpoints.up('md')]: {
    alignItems: 'center',
    flexDirection: 'row',
  },
}));

export const ToolbarLeftPanel = styled('div')(({ theme }) => ({
  display: 'flex',
  flexDirection: 'column',
  gap: theme.spacing(2),
  [theme.breakpoints.up('md')]: {
    flexDirection: 'row',
  },
}));

export const ToolbarRightPanel = styled('div')(({ theme }) => ({
  flexGrow: 1,
  display: 'flex',
  flexWrap: 'wrap',
  alignItems: 'center',
  justifyContent: 'flex-end',
  gap: theme.spacing(1),
}));
