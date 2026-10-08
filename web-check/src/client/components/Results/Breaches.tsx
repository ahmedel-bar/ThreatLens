import colors from 'client/styles/colors';
import { Card } from 'client/components/Form/Card';
import Row, { ExpandableRow } from 'client/components/Form/Row';

const cardStyles = `
  small {
    display: block;
    margin-top: 0.75rem;
    opacity: 0.5;
    a { color: ${colors.primary} }
  }
`;

const BreachesCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { domain, breaches = [] } = props.data;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons} styles={cardStyles}>
      <Row lbl="Domain" val={domain} />
      <Row lbl="Breaches" val={breaches.length ? `❌ ${breaches.length}` : '✅ None'} />
      {breaches.map((breach: any) => (
        <ExpandableRow
          key={breach.name}
          lbl={breach.title}
          val={`${breach.accounts.toLocaleString()} accounts`}
          rowList={[
            { lbl: 'Breach Date', val: breach.date },
            { lbl: 'Site', val: breach.domain },
            { lbl: 'Verified', val: breach.verified },
            { lbl: 'Data Exposed', val: '', listResults: breach.exposed },
            { lbl: 'Details', val: '', plaintext: breach.description },
          ]}
        />
      ))}
      <small>
        Source:{' '}
        <a href="https://haveibeenpwned.com/" target="_blank" rel="noreferrer">
          Have I Been Pwned
        </a>
      </small>
    </Card>
  );
};

export default BreachesCard;
