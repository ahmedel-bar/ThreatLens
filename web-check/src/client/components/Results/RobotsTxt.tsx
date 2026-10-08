import { Card } from 'client/components/Form/Card';
import Row, { type RowProps } from 'client/components/Form/Row';

const cardStyles = `
  grid-row: span 2;
`;

const RobotsTxtCard = (props: {
  data: { robots: RowProps[] };
  title: string;
  actionButtons: any;
}): JSX.Element => {
  const { data } = props;
  const robots = data?.robots || [];

  return (
    <Card heading={props.title} actionButtons={props.actionButtons} styles={cardStyles}>
      {robots.length === 0 && <p>No crawl rules found.</p>}
      {robots.map((row: RowProps, index: number) => {
        return <Row key={`${row.lbl}-${index}`} lbl={row.lbl} val={row.val} />;
      })}
    </Card>
  );
};

export default RobotsTxtCard;
