import { Fragment } from 'react';
import colors from 'client/styles/colors';
import { Card } from 'client/components/Form/Card';
import Heading from 'client/components/Form/Heading';
import Row, { ExpandableRow, ListRow } from 'client/components/Form/Row';

const regions = new Intl.DisplayNames(['en'], { type: 'region' });

// Rows shown when a tracker is expanded, skipping any that are unknown
const details = (tracker: any) =>
  [
    { lbl: 'Requests', val: String(tracker.requests) },
    ...tracker.hosts.map((host: string) => ({ lbl: 'Host', val: host })),
    { lbl: 'Based In', val: tracker.country && regions.of(tracker.country) },
    { lbl: 'Privacy Policy', val: tracker.privacyPolicy && 'View', link: tracker.privacyPolicy },
  ].filter((row) => row.val);

const TrackersCard = (props: { data: any; title: string; actionButtons: any }): JSX.Element => {
  const { requests, trackers = [], otherTrackers = [], unknown = [] } = props.data;
  const categories: string[] = [...new Set<string>(trackers.map((t: any) => t.category))];
  const companies = new Set(trackers.map((t: any) => t.company)).size;
  const found = trackers.length + otherTrackers.length + unknown.length;
  return (
    <Card heading={props.title} actionButtons={props.actionButtons}>
      <Row lbl="Requests Made" val={String(requests)} />
      {companies > 0 && <Row lbl="Companies" val={String(companies)} />}
      {!found && <Row lbl="Third Parties" val="✅ None" />}
      {categories.map((category) => (
        <Fragment key={category}>
          <Heading as="h4" size="small" align="left" color={colors.primary}>
            {category}
          </Heading>
          {trackers
            .filter((t: any) => t.category === category)
            .map((tracker: any) => (
              <ExpandableRow
                key={tracker.name}
                lbl={tracker.name}
                val={tracker.company}
                rowList={details(tracker)}
              />
            ))}
        </Fragment>
      ))}
      {otherTrackers.length > 0 && <ListRow title="Other Trackers" list={otherTrackers} />}
      {unknown.length > 0 && <ListRow title="Unrecognised" list={unknown} />}
    </Card>
  );
};

export default TrackersCard;
