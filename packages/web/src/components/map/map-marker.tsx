import type { MarkerProps } from 'react-map-gl/maplibre';
import type { Theme, SxProps } from '@mui/material/styles';

import { Marker } from 'react-map-gl/maplibre';

import { Iconify } from '../iconify';

// ----------------------------------------------------------------------

export type MapMarkerProps = MarkerProps & {
  sx?: SxProps<Theme>;
};

export function MapMarker({ sx, ...other }: MapMarkerProps) {
  return (
    <Marker {...other}>
      <Iconify
        width={26}
        icon="custom:location-fill"
        sx={[{ color: 'error.main' }, ...(Array.isArray(sx) ? sx : [sx])]}
      />
    </Marker>
  );
}
