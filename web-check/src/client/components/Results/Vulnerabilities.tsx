import styled from '@emotion/styled';
import colors from 'client/styles/colors';
import { Card } from 'client/components/Form/Card';
import Row from 'client/components/Form/Row';
import type { Vuln } from 'client/utils/result-processor';

const cardStyles = `
  ul {
    list-style: none;
    padding: 0;
    margin: 0.5rem 0 0 0;
    max-height: 22rem;
    overflow: auto;
    li {
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      column-gap: 0.5rem;
      padding: 0.25rem;
      border-bottom: 1px solid ${colors.primaryTransparent};
      &:last-child { border-bottom: none }
    }
    a {
      color: ${colors.textColor};
      &:hover { color: ${colors.primary} }
    }
    b { color: ${colors.danger} }
    small { color: ${colors.textColorSecondary} }
  }
`;

const AllClear = styled.p`
  color: ${colors.success};
  margin: 0.5rem 0;
`;

const VulnerabilitiesCard = (props: {
  data: any;
  title: string;
  actionButtons: any;
}): JSX.Element => {
  const vulns: Vuln[] = props.data.vulns || [];
  const exploited = vulns.filter((v) => v.kev).length;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons} styles={cardStyles}>
      {vulns.length === 0 ? (
        <AllClear>✅ No known active vulnerabilities</AllClear>
      ) : (
        <>
          <Row lbl="Known CVEs" val={vulns.length.toString()} />
          {exploited > 0 && <Row lbl="Actively exploited" val={exploited.toString()} />}
          <ul>
            {vulns.map((v) => (
              <li key={v.id}>
                <span>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${v.id}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {v.id}
                  </a>{' '}
                  {v.kev && (
                    <b title="In CISA's Known Exploited Vulnerabilities catalog">Exploited</b>
                  )}
                </span>
                <small>
                  {[
                    v.epss != null && `EPSS ${(v.epss * 100).toFixed(1)}%`,
                    v.cvss != null && `CVSS ${v.cvss}`,
                    v.port && `${v.product || 'Port'} ${v.port}`,
                  ]
                    .filter(Boolean)
                    .join(' · ')}
                </small>
              </li>
            ))}
          </ul>
        </>
      )}
    </Card>
  );
};

export default VulnerabilitiesCard;
