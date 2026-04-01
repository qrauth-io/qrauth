import type { Theme, SxProps } from '@mui/material/styles';
import type { MapRef, MapProps as ReactMapProps } from 'react-map-gl/maplibre';

import { lazy, Suspense } from 'react';

import Skeleton from '@mui/material/Skeleton';
import { styled } from '@mui/material/styles';

import { MAP_STYLES } from './map-styles';

// ----------------------------------------------------------------------

const LazyMap = lazy(() => import('react-map-gl/maplibre'));

export type MapProps = ReactMapProps & {
  sx?: SxProps<Theme>;
  ref?: React.RefObject<MapRef | null>;
};

export function Map({ ref, sx, ...other }: MapProps) {
  const renderFallback = () => (
    <Skeleton
      variant="rectangular"
      sx={{
        top: 0,
        left: 0,
        width: 1,
        height: 1,
        position: 'absolute',
      }}
    />
  );

  return (
    <MapRoot sx={sx}>
      <Suspense fallback={renderFallback()}>
        <LazyMap ref={ref} mapStyle={MAP_STYLES.light} {...other} />
      </Suspense>
    </MapRoot>
  );
}

// ----------------------------------------------------------------------

const MapRoot = styled('div')({
  width: '100%',
  overflow: 'hidden',
  position: 'relative',
});
