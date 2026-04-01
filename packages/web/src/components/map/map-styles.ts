import type { StyleSpecification, MapProps as ReactMapProps } from 'react-map-gl/maplibre';

import voyagerGl from './presets/voyager-gl.json';
import positronGl from './presets/positron-gl.json';
import darkMatterGl from './presets/dark-matter-gl.json';

// ----------------------------------------------------------------------

// https://basemaps.cartocdn.com/gl/positron-gl-style/style.json
const positron = positronGl as StyleSpecification;

// https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json
const darkMatter = darkMatterGl as StyleSpecification;

// https://basemaps.cartocdn.com/gl/voyager-gl-style/style.json
const voyager = voyagerGl as StyleSpecification;

export const MAP_STYLES = {
  light: positron,
  dark: darkMatter,
  neutral: voyager,
} satisfies Record<string, ReactMapProps['mapStyle']>;

export type MapStyleKey = keyof typeof MAP_STYLES;
