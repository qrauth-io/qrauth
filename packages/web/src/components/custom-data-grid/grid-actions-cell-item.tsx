import type { GridActionsCellItemProps } from '@mui/x-data-grid';

import { useMemo, Fragment } from 'react';
import { isExternalLink } from 'minimal-shared/utils';

import Link from '@mui/material/Link';
import { GridActionsCellItem } from '@mui/x-data-grid';
import { menuItemClasses } from '@mui/material/MenuItem';

import { RouterLink } from 'src/routes/components';

// ----------------------------------------------------------------------

type CustomGridActionsCellItemProps = GridActionsCellItemProps & {
  href?: string;
};

const getLinkProps = (href?: string) => {
  if (!href) return {};

  return isExternalLink(href)
    ? { component: Link, href, target: '_blank', rel: 'noopener noreferrer' }
    : { component: RouterLink, href };
};

export function CustomGridActionsCellItem({
  href,
  showInMenu,
  ...other
}: CustomGridActionsCellItemProps) {
  const linkProps = useMemo(() => getLinkProps(href), [href]);
  const Wrapper = href ? 'li' : Fragment;

  if (showInMenu) {
    return (
      <Wrapper {...(href && { className: menuItemClasses.root })}>
        <GridActionsCellItem
          {...(other as Extract<CustomGridActionsCellItemProps, { showInMenu?: true }>)}
          {...linkProps}
          showInMenu
        />
      </Wrapper>
    );
  }

  return (
    <GridActionsCellItem
      {...(other as Extract<CustomGridActionsCellItemProps, { showInMenu?: false }>)}
      {...linkProps}
      showInMenu={false}
    />
  );
}
