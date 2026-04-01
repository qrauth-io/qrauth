import { Popup } from 'react-map-gl/maplibre';

import { styled } from '@mui/material/styles';

// ----------------------------------------------------------------------

export type MapPopupProps = React.ComponentProps<typeof MapPopupRoot>;

export function MapPopup({ sx, children, ...other }: MapPopupProps) {
  return (
    <MapPopupRoot anchor="bottom" sx={sx} {...other}>
      {children}
    </MapPopupRoot>
  );
}

// ----------------------------------------------------------------------

const MapPopupRoot = styled(Popup)``;
